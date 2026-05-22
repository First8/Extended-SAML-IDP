const { firefox } = require('playwright');
const { baseUrl, realm, username, password } = require('./config');

const TEST_ALIAS = 'test-artifact-binding';
const FAKE_SSO_URL = 'https://example.com/sso';
const IDP_ENTITY_ID = 'test123';

async function handleLoginIfPresent(page) {
    const url = page.url();
    if (url.includes('/protocol/openid-connect/auth') || url.includes('login-actions') || url.includes('/login')) {
        console.log('Login page detected, logging in...');
        await page.fill('#username', username);
        await page.fill('#password', password);
        await page.click('#kc-login');
        await page.waitForTimeout(1000);
        return true;
    }
    return false;
}

(async () => {
    const browser = await firefox.launch({ headless: true });
    const page = await browser.newPage();

    page.on('framenavigated', async (frame) => {
        if (frame === page.mainFrame()) console.log('Navigated to:', frame.url());
    });

    page.on('dialog', async dialog => {
        console.log(`Dialog: "${dialog.message()}"`);
        await dialog.accept();
    });

    page.on('response', async response => {
        if (response.url().includes('/identity-provider/instances') && ['POST','DELETE'].includes(response.request().method())) {
            const status = response.status();
            console.log(`API ${response.request().method()} /identity-provider/instances → ${status}`);
            if (status >= 400) {
                try { console.log('API error:', await response.text()); } catch {}
            }
        }
    });

    // ── Login via realm page ──────────────────────────────────────────────────
    console.log('Navigating to realm page...');
    await page.goto(`${baseUrl}/realms/${realm}/samlconfig/pages/realm`);
    await page.waitForTimeout(500);
    await page.fill('#realmNameInput', 'master');
    await page.click('button:has-text("Login with Keycloak")');
    await page.waitForTimeout(1000);
    await handleLoginIfPresent(page);
    await page.waitForTimeout(1000);

    // Reload so the Keycloak adapter initialises via the active session cookie
    console.log('Reloading list page...');
    await page.reload();
    await page.waitForTimeout(1000);
    await handleLoginIfPresent(page);

    // Wait for realm dropdown to be populated, then select master
    await page.waitForFunction(() => document.querySelector('#Realms option[value="master"]') !== null, { timeout: 10000 });
    await page.selectOption('#Realms', 'master');

    // ── Navigate to Add Provider via the Add button on the list page ──────────
    console.log('\nOpening add provider page...');
    const addBtn = await page.$('a[href*="addprovider"], button:has-text("Add provider"), a:has-text("Add")');
    if (addBtn) {
        await addBtn.click();
    } else {
        await page.goto(`${baseUrl}/realms/${realm}/samlconfig/pages/addprovider`);
    }
    await page.waitForTimeout(1000);
    await handleLoginIfPresent(page);
    await page.waitForTimeout(500);

    // ── Disable "Use Entity Descriptor" ───────────────────────────────────────
    console.log('Disabling use entity descriptor...');
    const useEntityDescriptor = await page.$('#useEntityDescriptor');
    if (useEntityDescriptor && await useEntityDescriptor.evaluate(el => el.checked)) {
        const edLabel = await page.$('label:has(#useEntityDescriptor) span.slider');
        if (edLabel) await edLabel.click();
        else await useEntityDescriptor.evaluate(el => el.click());
        await page.waitForTimeout(500);
    }

    // ── Fill required fields ──────────────────────────────────────────────────
    console.log(`Filling alias: "${TEST_ALIAS}"`);
    await page.fill('#alias', TEST_ALIAS);
    console.log(`Filling IDP entity ID: "${IDP_ENTITY_ID}"`);
    await page.fill('#idpEntityId', IDP_ENTITY_ID);
    console.log(`Filling SSO URL: "${FAKE_SSO_URL}"`);
    await page.fill('#ssoServiceUrl', FAKE_SSO_URL);

    // ── Validate initial state of artifactBindingResponse ─────────────────────
    const artifactCheckbox = await page.$('#artifactBindingResponse');
    if (!artifactCheckbox) {
        console.log('ERROR: #artifactBindingResponse not found!');
        await browser.close();
        return;
    }
    await artifactCheckbox.scrollIntoViewIfNeeded();
    const initialState = await artifactCheckbox.evaluate(el => el.checked);
    console.log(`\n  artifactBindingResponse initial state: ${initialState}`);
    if (initialState !== false) {
        console.log('FAIL: expected initial state to be false');
    } else {
        console.log('  initial state is false ✓');
    }

    // ── Toggle artifactBindingResponse to true ────────────────────────────────
    const slider = await page.$('#artifactBindingResponse + span.slider');
    if (slider) await slider.click();
    else await artifactCheckbox.evaluate(el => el.click());
    const afterToggle = await artifactCheckbox.evaluate(el => el.checked);
    console.log(`  artifactBindingResponse after toggle: ${afterToggle}`);

    // ── Save ──────────────────────────────────────────────────────────────────
    console.log('\nSaving...');
    const submitBtn = await page.$('#submit');
    if (!submitBtn) {
        console.log('ERROR: #submit not found');
        await browser.close();
        return;
    }
    await submitBtn.click({ force: true });
    await page.waitForTimeout(1000);
    await handleLoginIfPresent(page);
    await page.waitForTimeout(1000);

    // ── Verify on editprovider page ───────────────────────────────────────────
    const currentUrl = page.url();
    console.log(`\nCurrent URL after save: ${currentUrl}`);
    if (!currentUrl.includes('editprovider')) {
        console.log('WARNING: not on editprovider page, navigating there...');
        await page.goto(`${baseUrl}/realms/${realm}/samlconfig/pages/list`);
        await page.waitForTimeout(1000);
        await handleLoginIfPresent(page);
        await page.waitForTimeout(500);
        await page.click(`text=${TEST_ALIAS}`);
        await page.waitForTimeout(1000);
        await handleLoginIfPresent(page);
        await page.waitForTimeout(500);
    }

    const editCheckbox = await page.$('#artifactBindingResponse');
    let allPassed = (initialState === false);
    if (!editCheckbox) {
        console.log('ERROR: #artifactBindingResponse not found on edit page!');
        allPassed = false;
    } else {
        const persisted = await editCheckbox.evaluate(el => el.checked);
        const pass = persisted === true;
        console.log(`  artifactBindingResponse on edit page: ${persisted} — ${pass ? 'PASS' : 'FAIL (expected true)'}`);
        allPassed = allPassed && pass;
    }

    // ── Delete from list page ─────────────────────────────────────────────────
    console.log('\nDeleting test provider from list...');
    await page.goto(`${baseUrl}/realms/${realm}/samlconfig/pages/list`);
    await page.waitForTimeout(1000);
    await handleLoginIfPresent(page);
    await page.waitForTimeout(1000);

    const deleteClicked = await page.evaluate((alias) => {
        const rows = document.querySelectorAll('table tr');
        for (const row of rows) {
            const cells = row.querySelectorAll('td');
            if (cells.length > 0 && cells[0].textContent.trim() === alias) {
                const btn = Array.from(row.querySelectorAll('button')).find(b => b.textContent.trim() === 'Delete');
                if (btn) { btn.click(); return true; }
            }
        }
        return false;
    }, TEST_ALIAS);

    if (!deleteClicked) {
        console.log('WARNING: could not find delete button for test provider');
    }
    await page.waitForTimeout(1000);

    const providers = await page.$$eval('table tr td:first-child', els => els.map(e => e.textContent.trim()));
    const deleted = !providers.includes(TEST_ALIAS);
    console.log(`  provider deleted: ${deleted ? 'PASS' : 'FAIL (still present in list)'}`);
    allPassed = allPassed && deleted;

    console.log(`\n${allPassed ? 'ALL TESTS PASSED' : 'SOME TESTS FAILED'}`);
    await browser.close();
})();
