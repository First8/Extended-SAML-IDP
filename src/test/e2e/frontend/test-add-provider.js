const { createBrowserSession, login, navigateToAddProvider, deleteProvider, getCheckboxState, toggleCheckbox, saveForm } = require('./helpers');
const config = require('./config');

const TEST_ALIAS = 'test-artifact-binding';
const FAKE_SSO_URL = 'https://example.com/sso';
const IDP_ENTITY_ID = 'test123';

(async () => {
    const { browser, page } = await createBrowserSession();

    await login(page, config);

    console.log('\nOpening add provider page...');
    await navigateToAddProvider(page, config);

    // Disable "Use Entity Descriptor" if it defaults to on
    console.log('Disabling use entity descriptor...');
    const useEntityDescriptor = await page.$('#useEntityDescriptor');
    if (useEntityDescriptor && await useEntityDescriptor.evaluate(el => el.checked)) {
        const edLabel = await page.$('label:has(#useEntityDescriptor) span.slider');
        if (edLabel) await edLabel.click();
        else await useEntityDescriptor.evaluate(el => el.click());
        await page.waitForTimeout(500);
    }

    // Fill required fields
    console.log(`Filling alias: "${TEST_ALIAS}"`);
    await page.fill('#alias', TEST_ALIAS);
    console.log(`Filling IDP entity ID: "${IDP_ENTITY_ID}"`);
    await page.fill('#idpEntityId', IDP_ENTITY_ID);
    console.log(`Filling SSO URL: "${FAKE_SSO_URL}"`);
    await page.fill('#ssoServiceUrl', FAKE_SSO_URL);

    // Validate initial state
    const initialState = await getCheckboxState(page, 'artifactBindingResponse');
    console.log(`\n  artifactBindingResponse initial state: ${initialState}`);
    let allPassed = initialState === false;
    if (!allPassed) console.log('FAIL: expected initial state to be false');
    else console.log('  initial state is false ✓');

    // Toggle to true
    const afterToggle = await toggleCheckbox(page, 'artifactBindingResponse');
    console.log(`  artifactBindingResponse after toggle: ${afterToggle}`);

    // Save
    console.log('\nSaving...');
    await saveForm(page, config);

    // Verify on edit page
    const currentUrl = page.url();
    console.log(`\nCurrent URL after save: ${currentUrl}`);
    if (!currentUrl.includes('editprovider')) {
        console.log('WARNING: not on editprovider page, navigating there...');
        await page.goto(`${config.baseUrl}/realms/${config.realm}/samlconfig/pages/list`);
        await page.waitForTimeout(1000);
        await page.click(`text=${TEST_ALIAS}`);
        await page.waitForTimeout(1000);
    }

    const persisted = await getCheckboxState(page, 'artifactBindingResponse');
    const pass = persisted === true;
    console.log(`  artifactBindingResponse on edit page: ${persisted} — ${pass ? 'PASS' : 'FAIL (expected true)'}`);
    allPassed = allPassed && pass;

    // Delete
    console.log('\nDeleting test provider from list...');
    const deleteClicked = await deleteProvider(page, config, TEST_ALIAS);
    if (!deleteClicked) console.log('WARNING: could not find delete button for test provider');

    const providers = await page.$$eval('table tr td:first-child', els => els.map(e => e.textContent.trim()));
    const deleted = !providers.includes(TEST_ALIAS);
    console.log(`  provider deleted: ${deleted ? 'PASS' : 'FAIL (still present in list)'}`);
    allPassed = allPassed && deleted;

    console.log(`\n${allPassed ? 'ALL TESTS PASSED' : 'SOME TESTS FAILED'}`);
    await browser.close();
})();
