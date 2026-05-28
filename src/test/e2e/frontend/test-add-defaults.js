const { createBrowserSession, login, navigateToAddProvider, deleteProvider, getCheckboxState, saveForm } = require('./helpers');
const config = require('./config');

const TEST_ALIAS   = 'test-defaults';
const FAKE_SSO_URL = 'https://example.com/sso';
const IDP_ENTITY_ID = 'test-defaults-entity';

// Expected default state of every boolean on the add-provider form.
// Verified from addprovider.html: only 'enabled' and 'useEntityDescriptor' carry the 'checked' attribute.
const EXPECTED_DEFAULTS = [
    { id: 'enabled',                              expected: true  },
    { id: 'useEntityDescriptor',                  expected: true  },
    { id: 'backchannel',                          expected: false },
    { id: 'id_token_hint',                        expected: false },
    { id: 'client_id_in_logout_requests',         expected: false },
    { id: 'allowCreate',                          expected: false },
    { id: 'httpPostBindingResponse',              expected: false },
    { id: 'artifactBindingResponse',              expected: false },
    { id: 'httpPostBindingAuthnRequest',          expected: false },
    { id: 'httpPostBindingLogout',                expected: false },
    { id: 'wantAuthnRequestsSigned',              expected: false },
    { id: 'wantAssertionsSigned',                 expected: false },
    { id: 'wantAssertionsEncrypted',              expected: false },
    { id: 'forceAuthentication',                  expected: false },
    { id: 'validateSignatures',                   expected: false },
    { id: 'signMetadata',                         expected: false },
    { id: 'passSubject',                          expected: false },
    { id: 'storeToken',                           expected: false },
    { id: 'storedTokensReadable',                 expected: false },
    { id: 'trustEmail',                           expected: false },
    { id: 'accountLinkingOnly',                   expected: false },
    { id: 'hideLoginPage',                        expected: false },
    { id: 'Artifact_Resolution',                  expected: false },
    { id: 'ArtifactResolutionService_in_metadata', expected: false },
    { id: 'Sign_Artifact_Resolution_Request',     expected: false },
    { id: 'Artifact_Resolution_with_SOAP',        expected: false },
    { id: 'Artifact_Resolution_with_XML_header',  expected: false },
    { id: 'Mutual_TLS',                           expected: false },
];

(async () => {
    const { browser, page } = await createBrowserSession();
    let allPassed = true;

    await login(page, config);

    console.log('\nOpening add provider page...');
    await navigateToAddProvider(page, config);

    // ── Check defaults of 'enabled' and 'useEntityDescriptor' before touching anything ──
    console.log('\n--- Checking defaults (before disabling useEntityDescriptor) ---');
    for (const { id, expected } of EXPECTED_DEFAULTS.slice(0, 2)) {
        const actual = await getCheckboxState(page, id);
        const pass = actual === expected;
        console.log(`  #${id}: ${actual} — ${pass ? 'PASS' : `FAIL (expected ${expected})`}`);
        allPassed = allPassed && pass;
    }

    // ── Disable useEntityDescriptor to reveal the remaining fields ────────────
    console.log('\nDisabling useEntityDescriptor to reveal remaining fields...');
    const useEntityDescriptor = await page.$('#useEntityDescriptor');
    if (useEntityDescriptor && await useEntityDescriptor.evaluate(el => el.checked)) {
        const slider = await page.$('#useEntityDescriptor + span.slider');
        if (slider) await slider.click();
        else await useEntityDescriptor.evaluate(el => el.click());
        await page.waitForTimeout(500);
    }

    // ── Fill required fields ──────────────────────────────────────────────────
    await page.fill('#alias', TEST_ALIAS);
    await page.fill('#idpEntityId', IDP_ENTITY_ID);
    await page.fill('#ssoServiceUrl', FAKE_SSO_URL);

    // ── Check defaults of all remaining booleans ──────────────────────────────
    console.log('\n--- Checking defaults (remaining fields) ---');
    for (const { id, expected } of EXPECTED_DEFAULTS.slice(2)) {
        const actual = await getCheckboxState(page, id);
        const pass = actual === expected;
        console.log(`  #${id}: ${actual} — ${pass ? 'PASS' : `FAIL (expected ${expected})`}`);
        allPassed = allPassed && pass;
    }

    // ── Save so the provider exists in a known-default state ──────────────────
    console.log('\nSaving provider with all defaults...');
    await saveForm(page, config);

    // ── Clean up ──────────────────────────────────────────────────────────────
    console.log('\nDeleting test provider...');
    const deleted = await deleteProvider(page, config, TEST_ALIAS);
    if (!deleted) {
        console.log('WARNING: could not find delete button for test provider');
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
