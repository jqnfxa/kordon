// Layer 4 of 5. Owns a Buffer and forwards the extent to it.
#ifndef KORDON_TESTDATA_ZLCTU_GRID_HPP
#define KORDON_TESTDATA_ZLCTU_GRID_HPP

#include "buffer.hpp"

namespace kordon_probe {

class Grid {
public:
    void allocate(int cells);
    void allocate_guarded(int cells);
    int extent() const { return m_cells.size(); }

private:
    Buffer m_cells;
};

}  // namespace kordon_probe

#endif
