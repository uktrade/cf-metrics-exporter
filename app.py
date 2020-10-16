import asyncio
import base64
import json
import os
import signal
import time

import aiohttp
from aiohttp import web
from dateutil.parser import isoparser

from app_utils import loop_forever, round_robin, normalise_environment


def Token(login_base, username, password, session):
    expires_at = time.monotonic()
    token = None

    async def _get():
        nonlocal token
        nonlocal expires_at

        if expires_at > time.monotonic():
            return token

        async with session.post(f'{login_base}oauth/token',
            headers={
                'Authorization': 'Basic ' + base64.b64encode(b'cf:').decode('ascii')
            },
            data={
                'username': username,
                'password': password,
                'grant_type': 'password',
            }) as resp:
            response = json.loads(await resp.text())

        token = response['access_token']
        expires_at = time.monotonic() + int(response['expires_in']) - 5  # 5 to avoid us thinking valid, but not CF

        return token

    return _get


def AuthenticatedRateLimitedRequester(session, get_token):
    can_make_request_at = time.time()

    async def _make_request(method, url, params=()):
        nonlocal can_make_request_at

        now = time.time()
        to_sleep = max(0, can_make_request_at - now)
        await asyncio.sleep(to_sleep)

        async with session.request(method, url, headers={'authorization': 'bearer ' + await get_token()}, params=dict(params)) as resp:
            now = time.time()

            remaining_amount = int(resp.headers['X-RateLimit-Remaining'])
            remaining_time = int(resp.headers['X-RateLimit-Reset']) - now
            time_until_next = remaining_time / remaining_amount

            can_make_request_at = now + time_until_next

            return json.loads(await resp.text())

    return _make_request


async def paginated_request(requester, url):
    while url:
        response = await next(requester)('get', url)

        resources = response['resources']
        for resource in resources:
            yield resource

        try:
            url = response['pagination']['next']['href']
        except (KeyError, TypeError):
            url = None


def get_spaces(api_base, make_request):
    return paginated_request(make_request, f'{api_base}v3/spaces')


def get_apps(api_base, make_request):
    return paginated_request(make_request, f'{api_base}v3/apps')


def get_processes(api_base, make_request):
    return paginated_request(make_request, f'{api_base}v3/processes')


async def get_process_stats(api_base, make_request, processes):
    datetime_parser = isoparser(sep='T')
    async for process in processes:

        stats = paginated_request(make_request, f'{api_base}v3/processes/{process["guid"]}/stats')

        try:
            async for s in stats:
                try:
                    yield process, (s['index'], s['usage'], int(datetime_parser.isoparse(s['usage']['time']).timestamp() * 1000))
                except KeyError:
                    # If process is down, we don't have metrics
                    pass

        except aiohttp.client_exceptions.ClientResponseError as er:
            # The process may have gone away
            continue


async def run_poller_and_server(port, login_base, api_base, users):
    metrics = dict()
    metrics_str = ''

    async with aiohttp.ClientSession(raise_for_status=True) as session:
        make_request = round_robin([
            AuthenticatedRateLimitedRequester(session, get_token)
            for user in users
            for get_token in [Token(login_base, user['USERNAME'], user['PASSWORD'], session)]
        ])

        async def poll():
            nonlocal metrics_str
            start = time.monotonic()
            print('Polling...', flush=True)

            spaces_by_guid = dict([(space['guid'], space) async for space in get_spaces(api_base, make_request)])
            apps_by_guid = dict([(app['guid'], app) async for app in get_apps(api_base, make_request)])

            processes = get_processes(api_base, make_request)
            process_stats = get_process_stats(api_base, make_request, processes)

            previous_keys = set(metrics.keys())
            new_keys = set()
            async for process, (i, stat, timestamp) in process_stats:
                app = apps_by_guid[process['relationships']['app']['data']['guid']]
                space = spaces_by_guid[app['relationships']['space']['data']['guid']]

                for name in ['cpu', 'mem', 'disk']:
                    key = f'{name}{{space="{space["name"]}",app="{app["name"]}",process="{process["type"]}",index="{i}"}}'
                    metrics[key] = (stat[name], timestamp)
                    new_keys.add(key)

                metrics_str = ''.join([
                    f'{key} {stat} {timestamp}\n'
                    for key, (stat, timestamp) in metrics.items()
                ])

            keys_to_remove = previous_keys - new_keys
            for key in keys_to_remove:
                del metrics[key]

            end = time.monotonic()
            print('Found metrics: {} chars, taking {} seconds'.format(len(metrics_str), end-start), flush=True)

        print('Starting poller', flush=True)
        poller_task = asyncio.create_task(loop_forever(poll))
        print('Started poller', flush=True)

        print('Starting server', flush=True)

        async def handle(request):
            print('Serving metrics: {} chars'.format(len(metrics_str)))
            return web.Response(text=str(metrics_str), content_type='text/plain')

        app = web.Application()
        app.add_routes([web.get('/metrics', handle)])

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, '0.0.0.0', port)
        await site.start()
        print('Started server', flush=True)

        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            print('Stopping server', flush=True)

            await site.stop()
            await app.shutdown()
            await runner.cleanup()

            print('Stopped server', flush=True)

            print('Stopping poller', flush=True)
            poller_task.cancel()
            try:
                await poller_task
            except asyncio.CancelledError:
                pass
            print('Stopped poller', flush=True)

            raise


async def async_main():
    env = normalise_environment(os.environ)

    port = int(env['PORT'])
    login_base = os.environ['LOGIN_BASE']
    api_base = os.environ['API_BASE']
    users = env['USERS']

    current_task = asyncio.current_task()
    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGINT, current_task.cancel)
    loop.add_signal_handler(signal.SIGTERM, current_task.cancel)

    try:
        await run_poller_and_server(port, login_base, api_base, users)
    except asyncio.CancelledError:
        pass


asyncio.run(async_main())
print("Exiting gracefully", flush=True)
