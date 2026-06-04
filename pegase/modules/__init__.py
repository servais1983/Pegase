"""Attack and support modules."""

from pegase.modules.base import Finding, Module, ModuleResult
from pegase.modules.netassault import NetAssault
from pegase.modules.recon import ReconSphere
from pegase.modules.socialmatrix import SocialMatrix
from pegase.modules.vulnmatrix import VulnMatrix
from pegase.modules.webbreacher import WebBreacher

__all__ = [
    "Finding",
    "Module",
    "ModuleResult",
    "NetAssault",
    "ReconSphere",
    "SocialMatrix",
    "VulnMatrix",
    "WebBreacher",
    "available_modules",
]


def available_modules() -> dict[str, type[Module]]:
    return {
        cls.name: cls
        for cls in (ReconSphere, NetAssault, WebBreacher, SocialMatrix, VulnMatrix)
    }
