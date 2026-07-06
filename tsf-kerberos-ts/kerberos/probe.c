/** @file
 * @brief Kerberos Group
 *
 * Obtain a TGT from a KDC with a principal and password, and log the
 * resulting ticket (client/server, validity, session-key enctype).
 * The realm/KDC/principal/password are the test's to supply via the
 * environment; with none configured the test skips cleanly - a host
 * with no KDC to point at is not a failure.
 *
 * Authorized use only: this authenticates to a real KDC/AD.
 *
 * Copyright (C) 2026 Interpretica Unipessoal Lda
 */

#define TE_TEST_NAME    "kerberos/probe"

#include "te_config.h"
#include <stdlib.h>
#include "tapi_test.h"
#include "te_string.h"

#include "tapi_kerberos.h"
#include "tsapi_kerberos.h"

int
main(int argc, char **argv)
{
    tsapi_kerberos_session sess = {0};
    tapi_krb5_ticket ticket;
    bool ticket_ready = false;
    bool ok = false;
    const char *principal;
    const char *password;

    TEST_START;

    principal = getenv("TSF_KRB5_PRINCIPAL");
    password = getenv("TSF_KRB5_PASSWORD");
    if (principal == NULL || principal[0] == '\0' ||
        password == NULL || password[0] == '\0')
    {
        TEST_SKIP("Set TSF_KRB5_PRINCIPAL and TSF_KRB5_PASSWORD "
                  "(and a resolvable realm/KDC) to probe a KDC");
    }

    TEST_STEP("Open a session to the agent");
    CHECK_RC(tsapi_kerberos_session_init(&sess, "pco_krb5_probe"));

    TEST_STEP("Get a TGT for %s", principal);
    CHECK_RC(tapi_krb5_get_tgt(sess.pco, principal, password, &ok, &ticket));
    ticket_ready = true;
    if (!ok)
        TEST_VERDICT("the KDC did not issue a TGT for %s", principal);

    RING("TGT: %s -> %s, enctype %s (id %d), valid %ld..%ld",
         ticket.client != NULL ? ticket.client : "?",
         ticket.server != NULL ? ticket.server : "?",
         ticket.enctype != NULL ? ticket.enctype : "?", ticket.enctype_id,
         ticket.starttime, ticket.endtime);

    if (ticket.client == NULL || ticket.client[0] == '\0')
        TEST_VERDICT("the TGT has no client principal");

    TEST_SUCCESS;

cleanup:
    if (ticket_ready)
        tapi_krb5_ticket_free(&ticket);
    tsapi_kerberos_session_fini(&sess);
    TEST_END;
}
