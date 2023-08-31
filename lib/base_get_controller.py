from typing import Any

from lib.utils import constants


class BaseGetConfigController:
    def get_logging(self):
        raise NotImplementedError("get_logging not implemented")

    def get_service(self):
        raise NotImplementedError("get_service not implemented")

    def get_network(self):
        raise NotImplementedError("get_network not implemented")

    def get_security(self):
        raise NotImplementedError("get_security not implemented")

    def get_namespace(self, for_mods: list[str] | None = None):
        raise NotImplementedError("get_namespace not implemented")

    def get_sets(self, for_mods: list[str] | None = None, flip=False):
        raise NotImplementedError("get_sets not implemented")

    def get_rack_ids(self):
        raise NotImplementedError("get_rack_ids not implemented")

    def get_xdr(self):
        raise NotImplementedError("get_xdr not implemented")

    def get_xdr_dcs(self, flip=False, for_mods: list[str] | None = None):
        raise NotImplementedError("get_xdr_dcs not implemented")

    def get_xdr_namespaces(self, for_mods: list[str] | None = None):
        raise NotImplementedError("get_xdr_namespaces not implemented")

    def get_xdr_filters(
        self,
        for_mods: list[str] | None = None,
        nodes: constants.NodeSelectionType = constants.NodeSelection.PRINCIPAL,
    ):
        raise NotImplementedError("get_xdr_filters not implemented")


# class BaseGetStatisticsController:
#     def get_service(self):
#         pass

#     def get_namespace(self, for_mods=None):
#         pass

#     def get_sets(self, for_mods=None, flip=False):
#         pass

#     def get_sindex(self):
#         pass

#     # TODO might be a good place to add support for the with modifier to filter nodes

#     def get_xdr(
#         self,
#     ) -> dict[str, Any]:  # type: ignore
#         pass

#     def get_xdr_dcs(self, for_mods: list[str] | None = None):
#         pass

#     def get_xdr_namespaces(self, for_mods=None):
#         pass


# class GetAclController:
#     def get_users(
#         self, nodes: constants.NodeSelectionType = constants.NodeSelection.ALL
#     ):
#         pass

#     def get_user(
#         self,
#         username: str,
#         nodes: constants.NodeSelectionType = constants.NodeSelection.ALL,
#     ):
#         pass

#     def get_roles(
#         self, nodes: constants.NodeSelectionType = constants.NodeSelection.ALL
#     ):
#         pass

#     def get_role(
#         self,
#         role_name,
#         nodes: constants.NodeSelectionType = constants.NodeSelection.ALL,
#     ):
#         pass
