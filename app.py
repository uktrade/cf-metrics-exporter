import asyncio
import base64
import json
import os
import signal
import time

import aiohttp
from aiohttp import web
from dateutil.parser import isoparser


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
    time_until_next = 0

    async def _make_request(method, url, params=()):
        nonlocal time_until_next

        await asyncio.sleep(time_until_next)

        async with session.request(method, url, headers={'authorization': 'bearer ' + await get_token()}, params=dict(params)) as resp:
            remaining_amount = int(resp.headers['X-RateLimit-Remaining'])
            remaining_time = int(resp.headers['X-RateLimit-Reset']) - time.time()
            time_until_next = remaining_time / remaining_amount

            return json.loads(await resp.text())

    return _make_request


async def paginated_request(requester, url):
    while url:
        response = await requester('get', url)

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


async def get_app_processes(api_base, make_request, apps):
    async for app in apps:
        processes = paginated_request(make_request, f'{api_base}v3/apps/{app["guid"]}/processes')

        try:
            async for process in processes:
                yield app, process
        except aiohttp.client_exceptions.ClientResponseError:
            # The app may have gone away
            pass


async def get_app_process_stats(api_base, make_request, app_processes):
    datetime_parser = isoparser(sep='T')
    async for (app, process) in app_processes:

        stats = paginated_request(make_request, f'{api_base}v3/processes/{process["guid"]}/stats')

        try:
            async for s in stats:
                try:
                    yield app, process, (s['index'], s['usage'], int(datetime_parser.isoparse(s['usage']['time']).timestamp()))
                except KeyError:
                    # If process is down, we don't have metrics
                    pass

        except aiohttp.client_exceptions.ClientResponseError as er:
            # The process may have gone away
            continue


async def async_main():
    port = int(os.environ['PORT'])

    login_base = os.environ['LOGIN_BASE']
    api_base = os.environ['API_BASE']
    username = os.environ['USERNAME']
    password = os.environ['PASSWORD']

    metrics_str = ''

    async with aiohttp.ClientSession(raise_for_status=True) as session:
        get_token = Token(login_base, username, password, session)
        make_request = AuthenticatedRateLimitedRequester(session, get_token)

        async def poll_metrics():
            nonlocal metrics_str
            while True:
                try:
                    start = time.monotonic()
                    print('Polling...', flush=True)
                    space_names = dict([(space['guid'], space['name']) async for space in get_spaces(api_base, make_request)])

                    apps = get_apps(api_base, make_request)
                    app_processes = get_app_processes(api_base, make_request, apps)
                    stats = get_app_process_stats(api_base, make_request, app_processes)

                    metrics_str = ''.join([
                        f'{name}{{space="{space_names[app["relationships"]["space"]["data"]["guid"]]}",app="{app["name"]}",process="{process["type"]}",index="{i}"}} {stat[name]} {timestamp}\n'
                        async for app, process, (i, stat, timestamp) in stats
                        for name in ['cpu', 'mem', 'disk']
                    ])
                    end = time.monotonic()
                    print('Found metrics: {} chars, taking {} seconds'.format(len(metrics_str), end-start), flush=True)
                except Exception as e:
                    print("Error", e)
                    await asyncio.sleep(60)

        poller_task = asyncio.create_task(poll_metrics())

        current_task = asyncio.current_task()
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGINT, current_task.cancel)
        loop.add_signal_handler(signal.SIGTERM, current_task.cancel)

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
            pass

        print('Stopping server', flush=True)

        await site.stop()
        await app.shutdown()
        await runner.cleanup()

        poller_task.cancel()
        try:
            await poller_task
        except asyncio.CancelledError:
            pass

        print('Stopped', flush=True)

asyncio.run(async_main())
