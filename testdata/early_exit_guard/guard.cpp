// Fixture: a real guard, then an unsigned subtraction -- 22 ways of writing
// "check, then leave", and which of them the underflow checks recognise.
//
// Reported by the user 2026-09-11: `if (<check>) { return; }` followed by an
// unsigned subtraction is still flagged as an error when the check is real.
// Measured the same day against the release binary at 9a9e02f: of the 22
// guarded functions below, 14 were flagged. Every guard here is genuine, so
// every finding in a `_good` function is a false positive, and the four
// `_bad` controls must stay flagged.
//
// Why each miss happens, from src/tools/clang_query.rs:
//   * EXIT_STATEMENTS is `return` or `throw` only, and a `throw` of a type
//     with a destructor is wrapped in an ExprWithCleanups the matcher does not
//     look through -- so `throw std::runtime_error(...)` does not count while
//     `throw Error{1}` does. `exit()`, `abort()`, `goto`, `continue`, `break`
//     and a `return` in the else branch are not exits either.
//   * the early-exit exemption is disabled by `unless(hasAncestor(ifStmt(
//     mentions)))`, which was meant to stop the defect's own `if` exempting
//     it but excludes a subtraction anywhere inside *any* later if that names
//     the variable (g12).
//   * GUARD_SHAPES has no member-field shape: `m_count - 1` can never be
//     exempted, however it is guarded (M14, M15, g16).
//   * an extent guard must be the *same accessor*: `empty()` does not exempt
//     `size() - 1`, `isEmpty()` does not exempt `width() - 1` (g17, g19) --
//     and that is the medium-confidence check, the one a reader sees.
//   * an explicit cast on the operand hides it from every shape (g20).
//
// @kordon cwe: 191
// @kordon confidence: low
// @kordon xfail: 14 of 22 real guards are not recognised -- integer lane TODO 6b

#include <cstddef>
#include <cstdlib>
#include <stdexcept>
#include <vector>

struct Image {
    std::size_t width() const { return w; }
    bool isEmpty() const { return w == 0; }
    std::size_t w;
};
struct Error { int code; };
void use(std::size_t);
bool ok(std::size_t);

// ------------------------------------------------------- must stay silent

// 1 early return, braces
void g01_brace_return_good(std::size_t n) { if (n == 0) { return; } use(n - 1); }
// 2 early return, no braces
void g02_bare_return_good(std::size_t n) { if (n == 0) return; use(n - 1); }
// 3 a statement before the return
void g03_log_then_return_good(std::size_t n) { if (n == 0) { use(0); return; } use(n - 1); }
// 4 throw of a type with a destructor -- FLAGGED
void g04_throw_class_good(std::size_t n) { if (n == 0) throw std::runtime_error("empty"); use(n - 1); }
// 5 throw of an aggregate, braces
void g05_throw_aggregate_good(std::size_t n) { if (n == 0) { throw Error{1}; } use(n - 1); }
// 6 exit() -- FLAGGED
void g06_exit_good(std::size_t n) { if (n == 0) std::exit(1); use(n - 1); }
// 7 abort() -- FLAGGED
void g07_abort_good(std::size_t n) { if (n == 0) { std::abort(); } use(n - 1); }
// 8 return in the else branch -- FLAGGED
void g08_else_return_good(std::size_t n) { if (n > 0) { use(1); } else { return; } use(n - 1); }
// 9 continue -- FLAGGED
void g09_continue_good(const std::vector<std::size_t> &v) { for (std::size_t n : v) { if (n == 0) continue; use(n - 1); } }
// 10 break -- FLAGGED
void g10_break_good(const std::vector<std::size_t> &v) { for (std::size_t n : v) { if (n == 0) break; use(n - 1); } }
// 11 goto -- FLAGGED
void g11_goto_good(std::size_t n) { if (n == 0) goto fail; use(n - 1); return; fail: use(0); }
// 12 early return, then the subtraction inside a second if naming n -- FLAGGED
void g12_second_if_lt_good(std::size_t n, bool f) { if (n == 0) return; if (f && n < 100) { use(n - 1); } }
// 13 early return, then the subtraction inside a second if on another variable
void g13_second_if_other_good(std::size_t n, bool f) { if (n == 0) return; if (f) { use(n - 1); } }
// 14 member field, early return -- FLAGGED
struct M14 {
    std::size_t m_count;
    void run_good() { if (m_count == 0) return; use(m_count - 1); }
};
// 15 member field, enclosing guard -- FLAGGED
struct M15 {
    std::size_t m_count;
    void run_good() { if (m_count > 0) { use(m_count - 1); } }
};
// 16 member through a pointer, early return -- FLAGGED
void g16_ptr_member_good(const M14 *p) { if (p->m_count == 0) return; use(p->m_count - 1); }
// 17 extent: empty() guards size() - 1 -- FLAGGED, at medium
void g17_empty_guard_good(const std::vector<int> &v) { if (v.empty()) return; use(v.size() - 1); }
// 18 extent: size() == 0 guards size() - 1
void g18_size_guard_good(const std::vector<int> &v) { if (v.size() == 0) return; use(v.size() - 1); }
// 19 extent: isEmpty() guards width() - 1 -- FLAGGED, at medium
void g19_isempty_guard_good(const Image &img) { if (img.isEmpty()) return; use(img.width() - 1); }
// 20 explicit cast on the operand -- FLAGGED
void g20_cast_good(int n) { if (n <= 0) return; use(static_cast<std::size_t>(n) - 1); }
// 21 a helper predicate naming n
void g21_helper_good(std::size_t n) { if (!ok(n)) return; use(n - 1); }
// 22 a ternary in the condition
void g22_ternary_good(std::size_t n) { if (n == 0 ? true : false) return; use(n - 1); }

// -------------------------------------------------------- must be flagged

void c01_unguarded_bad(std::size_t n) { use(n - 1); }
void c02_wrong_variable_bad(std::size_t n, std::size_t k) { if (k == 0) return; use(n - 1); }
// the guard evaluates the subtraction itself: a zero n wraps before it can help
void c03_guard_uses_subtraction_bad(std::size_t n, std::size_t x) { if (x > n - 1) { return; } use(x); }
// the condition runs after the body
void c04_do_while_bad(std::size_t n) { do { use(n - 1); } while (n > 0); }
