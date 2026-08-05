"""Attack and support modules."""

from pegase.modules.aibreacher import AIBreacher
from pegase.modules.base import Finding, Module, ModuleResult
from pegase.modules.cloudstrike import CloudStrike
from pegase.modules.mobilehunter import MobileHunter
from pegase.modules.netassault import NetAssault
from pegase.modules.physicalvector import PhysicalVector
from pegase.modules.postxploit import PostXploit
from pegase.modules.recon import ReconSphere
from pegase.modules.socialmatrix import SocialMatrix
from pegase.modules.toolforge import ToolForge
from pegase.modules.vulnmatrix import VulnMatrix
from pegase.modules.webbreacher import WebBreacher
from pegase.modules.wirelessphantom import WirelessPhantom

__all__ = [
    "Finding",
    "Module",
    "ModuleResult",
    "AIBreacher",
    "CloudStrike",
    "MobileHunter",
    "NetAssault",
    "PhysicalVector",
    "PostXploit",
    "ReconSphere",
    "SocialMatrix",
    "ToolForge",
    "VulnMatrix",
    "WebBreacher",
    "WirelessPhantom",
    "available_modules",
]


def available_modules() -> dict[str, type[Module]]:
    return {
        cls.name: cls
        for cls in (
            ReconSphere,
            NetAssault,
            WebBreacher,
            SocialMatrix,
            CloudStrike,
            MobileHunter,
            WirelessPhantom,
            PhysicalVector,
            ToolForge,
            VulnMatrix,
            PostXploit,
            AIBreacher,
        )
    }
