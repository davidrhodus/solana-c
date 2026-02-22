/*
 * fuzz_compute_budget_parse.c - Fuzz sol_compute_budget_parse
 */

#include <stddef.h>
#include <stdint.h>

#include "runtime/sol_compute_budget.h"
#include "txn/sol_transaction.h"

int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    sol_transaction_t tx;
    sol_err_t err = sol_transaction_decode(data, size, &tx);
    if (err != SOL_OK) return 0;

    sol_compute_budget_t budget;
    (void)sol_compute_budget_parse(&budget, &tx);
    return 0;
}

