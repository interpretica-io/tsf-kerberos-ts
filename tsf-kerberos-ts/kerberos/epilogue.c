/** @file
 * @brief Kerberos Group
 * Copyright (C) 2026 Interpretica Unipessoal Lda
 */
#define TE_TEST_NAME    "kerberos/epilogue"
#include "te_config.h"
#include "tapi_test.h"
int
main(int argc, char **argv)
{
    TEST_START;
    TEST_STEP("Kerberos group epilogue");
    TEST_SUCCESS;
cleanup:
    TEST_END;
}
