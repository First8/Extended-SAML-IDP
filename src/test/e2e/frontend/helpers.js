const { firefox } = require('playwright');

async function createBrowserSession() {
    const browser = await firefox.launch({ headless: true, slowMo: 0 });
    const page = await browser.newPage();

    page.on('framenavigated', frame => {
        if (frame === page.mainFrame()) console.log('Navigated to:', frame.url());
    });
    page.on('dialog', async dialog => {
        console.log(`Dialog: "${dialog.message()}"`);
        await dialog.accept();
    });
    page.on('response', async response => {
        if (response.url().includes('/identity-provider/instances') &&
            ['POST', 'DELETE'].includes(response.request().method())) {
            const status = response.status();
            console.log(`API ${response.request().method()} /identity-provider/instances → ${status}`);
            if (status >= 400) {
                try { console.log('API error:', await response.text()); } catch {}
            }
        }
    });

    return { browser, page };
}

async function handleLoginIfPresent(page, config) {
    const url = page.url();
    if (url.includes('/protocol/openid-connect/auth') || url.includes('login-actions') || url.includes('/login')) {
        console.log('Login page detected, logging in...');
        await page.fill('#username', config.username);
        await page.fill('#password', config.password);
        await page.click('#kc-login');
        await page.waitForTimeout(1000);
        return true;
    }
    return false;
}

async function login(page, config) {
    console.log('Navigating to realm page...');
    await page.goto(`${config.baseUrl}/realms/${config.realm}/samlconfig/pages/realm`);
    await page.waitForTimeout(500);
    await page.fill('#realmNameInput', config.realm);
    await page.click('button:has-text("Login with Keycloak")');
    await page.waitForTimeout(1000);
    await handleLoginIfPresent(page, config);
    await page.waitForTimeout(1000);

    console.log('Reloading list page...');
    await page.reload();
    await page.waitForTimeout(1000);
    await handleLoginIfPresent(page, config);

    await page.waitForFunction(
        r => document.querySelector(`#Realms option[value="${r}"]`) !== null,
        config.realm,
        { timeout: 10000 }
    );
    await page.selectOption('#Realms', config.realm);
}

async function navigateToEditProvider(page, config, providerName) {
    await page.goto(`${config.baseUrl}/realms/${config.realm}/samlconfig/pages/list`);
    await page.waitForTimeout(1000);
    await handleLoginIfPresent(page, config);
    await page.waitForTimeout(500);
    await page.click(`text=${providerName}`);
    await page.waitForTimeout(1000);
    await handleLoginIfPresent(page, config);
    await page.waitForTimeout(500);
}

async function navigateToAddProvider(page, config) {
    const addBtn = await page.$('a[href*="addprovider"], button:has-text("Add provider"), a:has-text("Add")');
    if (addBtn) {
        await addBtn.click();
    } else {
        await page.goto(`${config.baseUrl}/realms/${config.realm}/samlconfig/pages/addprovider`);
    }
    await page.waitForTimeout(1000);
    await handleLoginIfPresent(page, config);
    await page.waitForTimeout(500);
}

async function deleteProvider(page, config, alias) {
    await page.goto(`${config.baseUrl}/realms/${config.realm}/samlconfig/pages/list`);
    await page.waitForTimeout(1000);
    await handleLoginIfPresent(page, config);
    await page.waitForTimeout(1000);

    const deleteClicked = await page.evaluate(a => {
        const rows = document.querySelectorAll('table tr');
        for (const row of rows) {
            const cells = row.querySelectorAll('td');
            if (cells.length > 0 && cells[0].textContent.trim() === a) {
                const btn = Array.from(row.querySelectorAll('button')).find(b => b.textContent.trim() === 'Delete');
                if (btn) { btn.click(); return true; }
            }
        }
        return false;
    }, alias);

    await page.waitForTimeout(1000);
    return deleteClicked;
}

async function getCheckboxState(page, id) {
    const checkbox = await page.$(`#${id}`);
    if (!checkbox) throw new Error(`Checkbox #${id} not found`);
    await checkbox.scrollIntoViewIfNeeded();
    return checkbox.evaluate(el => el.checked);
}

async function toggleCheckbox(page, id) {
    const checkbox = await page.$(`#${id}`);
    if (!checkbox) throw new Error(`Checkbox #${id} not found`);
    await checkbox.scrollIntoViewIfNeeded();
    const slider = await page.$(`#${id} + span.slider`);
    if (slider) await slider.click();
    else await checkbox.evaluate(el => el.click());
    return checkbox.evaluate(el => el.checked);
}

async function saveForm(page, config) {
    const saveBtn = await page.$('button:has-text("Save"), button:has-text("Edit"), #submit, input[type="submit"]');
    if (!saveBtn) throw new Error('Save button not found');
    await saveBtn.click({ force: true });
    await page.waitForTimeout(1000);
    await handleLoginIfPresent(page, config);
    await page.waitForTimeout(1000);
}

// Create a provider with all-default boolean settings, leaving the browser on the edit page.
async function createProvider(page, config, alias) {
    await navigateToAddProvider(page, config);
    const useEntityDescriptor = await page.$('#useEntityDescriptor');
    if (useEntityDescriptor && await useEntityDescriptor.evaluate(el => el.checked)) {
        const slider = await page.$('#useEntityDescriptor + span.slider');
        if (slider) await slider.click();
        else await useEntityDescriptor.evaluate(el => el.click());
        await page.waitForTimeout(500);
    }
    await page.fill('#alias', alias);
    await page.fill('#idpEntityId', alias);
    await page.fill('#ssoServiceUrl', 'https://example.com/sso');
    await saveForm(page, config);
}

// Toggle checkbox on current edit page, save, navigate back to edit page, verify persisted.
async function toggleAndPersist(page, config, providerName, checkboxId) {
    const before = await getCheckboxState(page, checkboxId);
    console.log(`  ${checkboxId} before: ${before}`);
    const after = await toggleCheckbox(page, checkboxId);
    console.log(`  ${checkboxId} after toggle: ${after}`);
    await saveForm(page, config);
    await navigateToEditProvider(page, config, providerName);
    const persisted = await getCheckboxState(page, checkboxId);
    const pass = persisted === after;
    console.log(`  ${checkboxId} after reload: ${persisted} — ${pass ? 'PASS' : `FAIL (expected ${after})`}`);
    return { before, after, persisted, pass };
}

module.exports = {
    createBrowserSession,
    handleLoginIfPresent,
    login,
    navigateToEditProvider,
    navigateToAddProvider,
    createProvider,
    deleteProvider,
    getCheckboxState,
    toggleCheckbox,
    saveForm,
    toggleAndPersist,
};
