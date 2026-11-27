/* The FW_RULE 2.27 layout fw.rs asserts (src/windows/native/fw.rs), checked
 * against the Windows SDK header by the ES2N gate: cl /c fw_layout.c. Keep the
 * numbers in step with the const block in fw.rs. */
#include <windows.h>
#include <firewall.h>
#include <stddef.h>

#define AT(f, n) static_assert(offsetof(FW_RULE, f) == n, #f);
AT(pNext, 0)
AT(wSchemaVersion, 8)
AT(wszRuleId, 16)
AT(wszName, 24)
AT(wszDescription, 32)
AT(dwProfiles, 40)
AT(Direction, 44)
AT(wIpProtocol, 48)
AT(LocalPorts, 56)
AT(LocalAddresses, 104)
AT(RemoteAddresses, 176)
AT(LocalInterfaceIds, 248)
AT(dwLocalInterfaceTypes, 264)
AT(wszLocalApplication, 272)
AT(wszLocalService, 280)
AT(Action, 288)
AT(wFlags, 292)
AT(wszRemoteMachineAuthorizationList, 296)
AT(wszRemoteUserAuthorizationList, 304)
AT(wszEmbeddedContext, 312)
AT(PlatformValidityList, 320)
AT(Status, 336)
AT(Origin, 340)
AT(wszGPOName, 344)
AT(Reserved, 352)
AT(pMetaData, 360)
AT(wszLocalUserAuthorizationList, 368)
AT(wszPackageId, 376)
AT(wszLocalUserOwner, 384)
AT(dwTrustTupleKeywords, 392)
AT(OnNetworkNames, 400)
AT(wszSecurityRealmId, 416)
AT(wFlags2, 424)
AT(RemoteOutServerNames, 432)
AT(Fqbn, 448)
AT(compartmentId, 456)
static_assert(sizeof(FW_PORT_RANGE_LIST) == 16, "FW_PORT_RANGE_LIST");
static_assert(sizeof(FW_PORTS) == 24 && offsetof(FW_PORTS, Ports) == 8, "FW_PORTS");
static_assert(sizeof(FW_ADDRESSES) == 72 && offsetof(FW_ADDRESSES, V4SubNets) == 8, "FW_ADDRESSES");
static_assert(sizeof(FW_ICMP_TYPE_CODE_LIST) == 16, "FW_ICMP_TYPE_CODE_LIST");
static_assert(offsetof(FW_RULE, RemotePorts) == 80, "RemotePorts");
/* A newer header may append fields after compartmentId; 2.27 ends there. */
static_assert(sizeof(FW_RULE) >= 464, "FW_RULE");
static_assert(FW_CURRENT_BINARY_VERSION >= 0x021B, "binary version");
