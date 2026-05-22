const { firefox } = require('playwright');
const { baseUrl, realm, username, password } = require('./config');

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

async function openEditPage(page, providerName) {
    await page.goto(`${baseUrl}/realms/${realm}/samlconfig/pages/list`);
    await page.waitForTimeout(1000);
    await handleLoginIfPresent(page);
    await page.waitForTimeout(500);
    await page.click(`text=${providerName}`);
    await page.waitForTimeout(1000);
    await handleLoginIfPresent(page);
    await page.waitForTimeout(500);
}

async function toggleAndSave(page, providerName) {
    const checkbox = await page.$('#artifactBindingResponse');
    if (!checkbox) { console.log('ERROR: #artifactBindingResponse not found!'); return null; }

    await checkbox.scrollIntoViewIfNeeded();
    const before = await checkbox.evaluate(el => el.checked);
    console.log(`  before: ${before}`);

    const slider = await page.$('#artifactBindingResponse + span.slider');
    if (slider) await slider.click();
    else await checkbox.evaluate(el => el.click());
    const after = await checkbox.evaluate(el => el.checked);
    console.log(`  after toggle: ${after}`);

    const saveBtn = await page.$('button:has-text("Save"), button:has-text("Edit"), input[type="submit"]');
    if (saveBtn) { await saveBtn.click(); await page.waitForTimeout(1000); }
    else { console.log('WARNING: save button not found'); }

    return { before, after };
}

async function verifyPersisted(page, providerName, expected) {
    await openEditPage(page, providerName);
    const checkbox = await page.$('#artifactBindingResponse');
    if (!checkbox) { console.log('ERROR: #artifactBindingResponse not found after reload!'); return false; }
    const persisted = await checkbox.evaluate(el => el.checked);
    const pass = persisted === expected;
    console.log(`  after reload: ${persisted} — ${pass ? 'PASS' : `FAIL (expected ${expected})`}`);
    return pass;
}

(async () => {
    const browser = await firefox.launch({ headless: true });
    const page = await browser.newPage();

    page.on('framenavigated', async (frame) => {
        if (frame === page.mainFrame()) console.log('Navigated to:', frame.url());
    });

    // Navigate to realm page, fill realm name and click login button
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

    // Wait for the providers table to appear
    await page.waitForSelector('table tr td:first-child', { timeout: 10000 });
    const providers = await page.$$eval('table tr td:first-child', els => els.map(e => e.textContent.trim()));
    console.log('Providers found:', providers);
    if (providers.length === 0) {
        console.log('No providers found.');
        await browser.close();
        return;
    }

    const providerName = providers[0];
    let allPassed = true;

    // Transition 1: read current state, toggle it, verify
    console.log(`\n--- Transition 1: toggle current state ---`);
    await page.click(`text=${providerName}`);
    await page.waitForTimeout(1000);
    await handleLoginIfPresent(page);
    await page.waitForTimeout(500);

    const t1 = await toggleAndSave(page, providerName);
    if (t1) {
        const pass1 = await verifyPersisted(page, providerName, t1.after);
        allPassed = allPassed && pass1;

        // Transition 2: toggle back to original state, verify
        console.log(`\n--- Transition 2: toggle back ---`);
        const t2 = await toggleAndSave(page, providerName);
        if (t2) {
            const pass2 = await verifyPersisted(page, providerName, t2.after);
            allPassed = allPassed && pass2;
        }
    }

    console.log(`\n${allPassed ? 'ALL TESTS PASSED' : 'SOME TESTS FAILED'}`);
    await browser.close();
})();
