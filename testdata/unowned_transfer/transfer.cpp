// Fixture: a fresh allocation handed to a class that cannot release it.
//
// Synthetic. Modelled on a real genetic-algorithm class constructed with four
// `new` expressions as arguments, storing all four in raw pointer members and
// declaring no destructor. Nothing ever freed them, and the construction was a
// button-click handler.
//
// Two engines should have caught that and structurally cannot, which is why
// this check exists:
//
//   * owning-memory fires on a `new` *assigned* to a non-owner. These are
//     constructor arguments, never assigned.
//   * special-member-functions fires when a class declares *some* special
//     member and omits the rest. This class declares none at all -- the worse
//     case, and the invisible one.
//
// The safe twins are what keep it honest: a non-owning back-reference and a
// class that expresses ownership in its member type are both extremely common,
// and flagging either would make the check unusable.

#include <memory>

namespace kordon_probe {

struct Strategy {
    virtual ~Strategy() = default;
    virtual int apply(int x) const = 0;
};

struct Doubler : Strategy {
    int apply(int x) const override { return x * 2; }
};

// ------------------------------------------------------------- must be flagged

// Raw pointer member, no destructor: no release path exists.
class NoReleasePath {
public:
    explicit NoReleasePath(Strategy *s) : m_strategy(s) {}
    int run(int x) const { return m_strategy->apply(x); }

private:
    Strategy *m_strategy;
};

// ------------------------------------------------------------ must stay silent

// Releases what it was given.
class Releases {
public:
    explicit Releases(Strategy *s) : m_strategy(s) {}
    ~Releases() { delete m_strategy; }
    Releases(const Releases &) = delete;
    Releases &operator=(const Releases &) = delete;

private:
    Strategy *m_strategy;
};

// Ownership expressed in the member's type, which is the fix for the case
// above and is what the same real codebase did in its other class.
class Owns {
public:
    explicit Owns(Strategy *s) : m_strategy(s) {}

private:
    std::unique_ptr<Strategy> m_strategy;
};

// A non-owning back-reference. Nothing is allocated at the call site, so there
// is nothing to release and no claim to make.
class Observes {
public:
    explicit Observes(Strategy *s) : m_watched(s) {}

private:
    Strategy *m_watched;
};

void call_sites(Strategy *existing)
{
    NoReleasePath leaks(new Doubler);
    Releases      released(new Doubler);
    Owns          owned(new Doubler);
    Observes      observer(existing);

    (void)leaks;
    (void)released;
    (void)owned;
    (void)observer;
}

}  // namespace kordon_probe
