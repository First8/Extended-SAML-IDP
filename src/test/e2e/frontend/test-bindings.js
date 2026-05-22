const { createBrowserSession, login, createProvider, deleteProvider, toggleAndPersist } = require('./helpers');
const config = require('./config');

const TEST_ALIAS = 'test-bindings';

const CHECKBOXES = [
    'httpPostBindingResponse',
    'httpPostBindingAuthnRequest',
    'httpPostBindingLogout',
];

(async () => {
    const { browser, page } = await createBrowserSession();
    let allPassed = true;

    await login(page, config);

    console.log(`\nCreating test provider "${TEST_ALIAS}"...`);
    await createProvider(page, config, TEST_ALIAS);

    for (const id of CHECKBOXES) {
        console.log(`\n--- ${id} ---`);
        const result = await toggleAndPersist(page, config, TEST_ALIAS, id);
        allPassed = allPassed && result.pass;
    }

    console.log('\nDeleting test provider...');
    const deleteClicked = await deleteProvider(page, config, TEST_ALIAS);
    if (!deleteClicked) {
        console.log('WARNING: could not find delete button');
        allPassed = false;
    } else {
        const providers = await page.$$eval('table tr td:first-child', els => els.map(e => e.textContent.trim()));
        const gone = !providers.includes(TEST_ALIAS);
        console.log(`  provider deleted: ${gone ? 'PASS' : 'FAIL (still present in list)'}`);
        allPassed = allPassed && gone;
    }

    console.log(`\n${allPassed ? 'ALL TESTS PASSED' : 'SOME TESTS FAILED'}`);
    await browser.close();
})();
