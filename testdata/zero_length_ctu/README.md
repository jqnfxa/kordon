# Fixture: a zero-length allocation four translation units from its cause

`new double[0]` succeeds. It returns a distinct, non-null pointer to an array
of zero elements, so there is no null to check and no allocation failure to
report — and indexing it at all is undefined behaviour.

    m_count = count;
    m_data  = new double[m_count];
    m_data[0] = 0.0;          // count == 0 -> out-of-bounds write

The extent is what decides this, and the extent is not in the file that
contains the write. It is a literal `0` in `app.cpp`, four cross-TU hops away:

    app.cpp     run_empty()          -- the only file containing the zero
      -> config.cpp  Scene::apply(0)
        -> mesh.cpp    Mesh::build(0)          cells = vertices * 2
          -> grid.cpp    Grid::allocate(0)
            -> buffer.cpp  Buffer::init(0)     <- the defect

`testdata/zero_length_tu_gate/` is the same defect with the call site in the
same file. This is the version that actually needs CTU.

## What must happen

| | expected |
|---|---|
| `kordon testdata/zero_length_ctu` | **nothing** — 0 defects |
| `kordon testdata/zero_length_ctu --ctu` | **CWE-787** at `buffer.cpp:25`, and only there |

```bash
kordon testdata/zero_length_ctu --ctu --require-cwe 787   # exit 0
kordon testdata/zero_length_ctu       --require-cwe 787   # exit 1
```

`Buffer::init_guarded` is the negative control: byte-identical allocation
reached by a byte-identical four-hop chain, differing only in an early return
on the zero-element case. It must never be flagged. A check that fires on both
is matching the shape and not the defect.

## Two ways this fixture silently stopped testing anything

Both were measured, and both produced a *passing* fixture that proved nothing.
They are recorded because either is easy to reintroduce.

**A defensive clamp manufactured a zero next to the sink.** `Grid::allocate`
originally read `if (cells < 0) { cells = 0; }`. That is a concrete zero one
hop from the write, so the analyzer found the defect from `grid.cpp` and never
followed the chain — deleting `app.cpp` entirely changed nothing. It is now an
early `return`. The ablation is the test: **remove `app.cpp`, and with `--ctu`
the finding must disappear.** If it survives, some layer is producing the zero
itself and the fixture is measuring one hop, not four.

**An accessor read the buffer on both paths.** `Buffer::first()` returned
`m_data[0]`, called through `Grid::sample` → `Mesh::probe` →
`Scene::first_sample` from both entry points. That is a real out-of-bounds
*read*, on the guarded chain too, so the negative control failed for a reason
that had nothing to do with the guard. The accessor chain now returns
`m_count`.

The `delete[] m_data;` at the top of both methods is there for the same
reason: without it both are genuine reinit-without-free (CWE-401), which
Kordon reports at high confidence on the good variant as well as the bad one.

## The ceiling: 8 translation units, and it is one flag

Generating the same chain at N hops (script in the session scratchpad, trivial
to rewrite) puts the limit exactly here:

| hops | reported |
|---|---|
| 4, 6, 8 | yes |
| 9, 10, 14 | **no** |

It is not the inlining budget. `analyzer-inline-max-stack-depth=20` and
`max-nodes=900000` both leave a 9-hop chain undetected. The control is
**`ctu-import-cpp-threshold`, whose default is 8** — "the maximal amount of
translation units that is considered for import when inlining functions during
CTU analysis of C++ source files". Measured on the 9-hop chain with everything
else held fixed:

```
ctu-import-cpp-threshold=8  -> 0 warnings
ctu-import-cpp-threshold=9  -> 1 warning
ctu-import-cpp-threshold=32 -> 1 warning
```

It counts **translation units imported along one path**, not call depth, so
the budget is spent by any wide fan-out and not only by deep chains. Kordon
does not currently set it. Raising it costs analysis time; the honest position
is that a chain crossing more than 8 units is out of reach today and the
report does not say so.
