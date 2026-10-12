import asyncio
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch
from fastapi import FastAPI
from fastapi.testclient import TestClient
import screenshots

class CaptureTests(unittest.IsolatedAsyncioTestCase):
    async def test_unresolved_domain_skips_browser(self):
        with patch('screenshots._capture', new_callable=AsyncMock) as capture:
            result = await screenshots.capture_page('missing.example', {'nxdomain': True, 'resolves': False})
            self.assertEqual(result['status'], 'skipped')
            capture.assert_not_awaited()

    async def test_metadata_returned(self):
        evidence = {'status': 'captured', 'path': '/screenshots/' + 'a' * 32 + '.png'}
        with patch('screenshots._capture', new_callable=AsyncMock, return_value=evidence):
            self.assertEqual(await screenshots.capture_page('example.com', {'resolves': True}), evidence)

    async def test_browser_failure_does_not_fail_scan(self):
        with patch('screenshots._capture', new_callable=AsyncMock, side_effect=RuntimeError('failed')):
            self.assertEqual((await screenshots.capture_page('example.com', {'resolves': True}))['status'], 'unavailable')

    async def test_timeout_reported(self):
        with patch('screenshots._capture', new_callable=AsyncMock, side_effect=asyncio.TimeoutError):
            self.assertIn('35-second', (await screenshots.capture_page('example.com', {'resolves': True}))['reason'])

    async def test_cancellation_propagates(self):
        with patch('screenshots._capture', new_callable=AsyncMock, side_effect=asyncio.CancelledError):
            with self.assertRaises(asyncio.CancelledError):
                await screenshots.capture_page('example.com', {'resolves': True})

    async def test_private_and_mixed_dns_blocked(self):
        for addresses in [['127.0.0.1'], ['10.0.0.1'], ['169.254.169.254'], ['::1'], ['93.184.216.34', '192.168.1.1']]:
            with patch('screenshots.socket.getaddrinfo', return_value=[(None, None, None, None, (a, 443)) for a in addresses]):
                self.assertFalse(await screenshots.public_url('https://example.com'))

    async def test_public_dns_allowed(self):
        with patch('screenshots.socket.getaddrinfo', return_value=[(None, None, None, None, ('93.184.216.34', 443))]):
            self.assertTrue(await screenshots.public_url('https://example.com'))

    async def test_non_web_urls_and_credentials_blocked(self):
        for url in ['file:///etc/passwd', 'ftp://example.com', 'https://user:pass@example.com']:
            self.assertFalse(await screenshots.public_url(url))

    async def test_scan_attaches_screenshot_preserving_verdict(self):
        import main
        dns = {'resolves': True, 'nxdomain': False, 'cname_target': None, 'a_records': ['93.184.216.34']}
        http = {'status': 200, 'title': 'Example', 'attempted': True}
        rules = {'verdict': 'clean', 'severity': 'info', 'provider': None, 'reason': 'No issues', 'confidence': 0, 'fingerprint_evidence': {}}
        shot = {'status': 'captured', 'path': '/screenshots/' + 'b' * 32 + '.png'}
        with patch('main.resolve_dns', return_value=dns), patch('main.fetch_http', new_callable=AsyncMock, return_value=http), patch('main.rule_based_analysis', return_value=rules), patch('main.capture_page', new_callable=AsyncMock, return_value=shot):
            result = await main.scan_domain('example.com', False)
            self.assertEqual(result['screenshot'], shot)
            self.assertEqual(result['verdict'], 'clean')

class ImageRouteTests(unittest.TestCase):
    def test_images_and_invalid_paths(self):
        app = FastAPI(); app.include_router(screenshots.router)
        client = TestClient(app)
        with tempfile.TemporaryDirectory() as folder, patch('screenshots.SCREENSHOT_DIR', Path(folder)):
            name = 'c' * 32 + '.png'
            (Path(folder) / name).write_bytes(b'\x89PNG\r\n\x1a\n')
            response = client.get('/screenshots/' + name)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers['content-type'], 'image/png')
            self.assertEqual(client.get('/screenshots/not-an-image').status_code, 404)
            self.assertEqual(client.get('/screenshots/' + 'd' * 32 + '.png').status_code, 404)
            self.assertEqual(client.post('/screenshots/capture').status_code, 405)

if __name__ == '__main__':
    unittest.main()

class BrowserFlowTests(unittest.IsolatedAsyncioTestCase):
    async def test_https_fallback_writes_image_and_closes_browser(self):
        from unittest.mock import Mock
        from playwright.async_api import Error
        page = AsyncMock()
        page.on = Mock()
        page.goto.side_effect = [Error('HTTPS unavailable'), Mock(status=200)]
        page.url = 'http://example.com/'
        page.screenshot.return_value = b'\x89PNG\r\n\x1a\n'
        context = AsyncMock(); context.on = Mock(); context.new_page.return_value = page
        browser = AsyncMock(); browser.new_context.return_value = context
        runtime = AsyncMock(); runtime.chromium.launch.return_value = browser
        manager = AsyncMock(); manager.__aenter__.return_value = runtime
        with tempfile.TemporaryDirectory() as folder, patch('screenshots.SCREENSHOT_DIR', Path(folder)), patch('screenshots.public_url', new_callable=AsyncMock, return_value=True), patch('playwright.async_api.async_playwright', return_value=manager):
            result = await screenshots._capture('example.com')
            self.assertEqual(result['status'], 'captured')
            self.assertTrue(result['https_fallback'])
            self.assertTrue((Path(folder) / result['path'].split('/')[-1]).is_file())
            self.assertEqual(page.goto.await_args_list[0].args[0], 'https://example.com/')
            self.assertEqual(page.goto.await_args_list[1].args[0], 'http://example.com/')
            browser.close.assert_awaited_once()

    async def test_navigation_failures_leave_no_fake_image(self):
        from unittest.mock import Mock
        from playwright.async_api import Error
        page=AsyncMock(); page.on=Mock(); page.goto.side_effect=Error('Connection refused')
        context=AsyncMock(); context.on=Mock(); context.new_page.return_value=page
        browser=AsyncMock(); browser.new_context.return_value=context
        runtime=AsyncMock(); runtime.chromium.launch.return_value=browser
        manager=AsyncMock(); manager.__aenter__.return_value=runtime
        with patch('screenshots.public_url', new_callable=AsyncMock, return_value=True), patch('playwright.async_api.async_playwright', return_value=manager):
            result=await screenshots._capture('example.com')
            self.assertEqual(result['status'],'unavailable')
            page.screenshot.assert_not_awaited()
            browser.close.assert_awaited_once()
