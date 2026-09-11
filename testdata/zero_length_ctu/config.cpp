#include "config.hpp"

namespace kordon_probe {

void Scene::apply(int resolution)
{
    m_mesh.build(resolution);
}

void Scene::apply_guarded(int resolution)
{
    m_mesh.build_guarded(resolution);
}

}  // namespace kordon_probe
