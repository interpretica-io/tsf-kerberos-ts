/** @file
 * @brief Kerberos Group
 *
 * Read a KDC's Kerberos posture with tapi_krb5_audit() and gate on it:
 * a principal that needs no pre-authentication (AS-REP roasting) and
 * weak session-key enctypes are the findings that matter. The realm/
 * KDC/principal(s)/password are the test's to supply via the
 * environment; with none configured the test skips cleanly.
 *
 * Authorized use only: this talks to a real KDC/AD.
 *
 * Copyright (C) 2026 Interpretica Unipessoal Lda
 */

#define TE_TEST_NAME    "kerberos/audit"

#include "te_config.h"
#include <stdlib.h>
#include "tapi_test.h"
#include "te_string.h"

#include "tapi_cybersec.h"
#include "tapi_kerberos.h"
#include "tapi_kerberos_audit.h"
#include "tsapi_kerberos.h"

int
main(int argc, char **argv)
{
    tsapi_kerberos_session sess = {0};
    tapi_krb5_audit_policy policy;
    tapi_cybersec_report report;
    te_string verdict = TE_STRING_INIT;
    bool report_ready = false;
    const char *principal;
    const char *password;
    const char *preauth_principal;

    TEST_START;

    principal = getenv("TSF_KRB5_PRINCIPAL");
    password = getenv("TSF_KRB5_PASSWORD");
    preauth_principal = getenv("TSF_KRB5_PREAUTH_PRINCIPAL");
    /* A realm/KDC must be resolvable; at least one probe target is needed. */
    if ((principal == NULL || principal[0] == '\0') &&
        (preauth_principal == NULL || preauth_principal[0] == '\0'))
    {
        TEST_SKIP("Set TSF_KRB5_PRINCIPAL(+PASSWORD) and/or "
                  "TSF_KRB5_PREAUTH_PRINCIPAL to assess a KDC");
    }

    TEST_STEP("Open a session to the agent");
    CHECK_RC(tsapi_kerberos_session_init(&sess, "pco_krb5_audit"));

    TEST_STEP("Read the Kerberos posture into a report");
    memset(&policy, 0, sizeof(policy));
    policy.principal = principal;
    policy.password = password;
    policy.preauth_principal = preauth_principal;

    tapi_cybersec_report_init(&report);
    report_ready = true;
    CHECK_RC(tapi_krb5_audit(sess.pco, &policy, &report));
    tapi_cybersec_report_log(&report);

    TEST_STEP("The report is well-formed (at least one finding)");
    if (tapi_cybersec_report_count(&report, TAPI_CYBERSEC_SEV_INFO) == 0)
        TEST_VERDICT("the Kerberos audit produced no findings");

    TEST_STEP("Gate: fail on anything at least HIGH (preauth-not-required)");
    if (tapi_cybersec_report_verdict(&report, TAPI_CYBERSEC_SEV_HIGH,
                                     &verdict))
    {
        TEST_VERDICT("%s", verdict.ptr);
    }

    TEST_SUCCESS;

cleanup:
    te_string_free(&verdict);
    if (report_ready)
        tapi_cybersec_report_free(&report);
    tsapi_kerberos_session_fini(&sess);
    TEST_END;
}
