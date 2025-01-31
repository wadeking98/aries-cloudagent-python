"""Credential schema admin routes."""

import json

from asyncio import shield

from aiohttp import web
from aiohttp_apispec import (
    docs,
    match_info_schema,
    querystring_schema,
    request_schema,
    response_schema,
)

from marshmallow import fields
from marshmallow.validate import Regexp

from ...admin.request_context import AdminRequestContext
from ...indy.issuer import IndyIssuer, IndyIssuerError
from ...ledger.base import BaseLedger
from ...ledger.error import LedgerError
from ...protocols.endorse_transaction.v1_0.manager import TransactionManager
from ...protocols.endorse_transaction.v1_0.models.transaction_record import (
    TransactionRecordSchema,
)
from ...storage.base import BaseStorage
from ...storage.error import StorageError

from ..models.openapi import OpenAPISchema
from ..valid import B58, NATURAL_NUM, INDY_SCHEMA_ID, INDY_VERSION

from .util import SchemaQueryStringSchema, SCHEMA_SENT_RECORD_TYPE, SCHEMA_TAGS


class SchemaSendRequestSchema(OpenAPISchema):
    """Request schema for schema send request."""

    schema_name = fields.Str(
        required=True,
        description="Schema name",
        example="prefs",
    )
    schema_version = fields.Str(
        required=True, description="Schema version", **INDY_VERSION
    )
    attributes = fields.List(
        fields.Str(
            description="attribute name",
            example="score",
        ),
        required=True,
        description="List of schema attributes",
    )


class SchemaSendResultSchema(OpenAPISchema):
    """Result schema content for schema send request with auto-endorse."""

    schema_id = fields.Str(
        description="Schema identifier", required=True, **INDY_SCHEMA_ID
    )
    schema = fields.Dict(description="Schema result", required=True)


class TxnOrSchemaSendResultSchema(OpenAPISchema):
    """Result schema for schema send request."""

    sent = fields.Nested(
        SchemaSendResultSchema(),
        required=False,
        description="Content sent",
    )
    txn = fields.Nested(
        TransactionRecordSchema(),
        required=False,
        description="Schema transaction to endorse",
    )


class SchemaSchema(OpenAPISchema):
    """Content for returned schema."""

    ver = fields.Str(description="Node protocol version", **INDY_VERSION)
    ident = fields.Str(data_key="id", description="Schema identifier", **INDY_SCHEMA_ID)
    name = fields.Str(
        description="Schema name",
        example=INDY_SCHEMA_ID["example"].split(":")[2],
    )
    version = fields.Str(description="Schema version", **INDY_VERSION)
    attr_names = fields.List(
        fields.Str(
            description="Attribute name",
            example="score",
        ),
        description="Schema attribute names",
        data_key="attrNames",
    )
    seqNo = fields.Int(description="Schema sequence number", strict=True, **NATURAL_NUM)


class SchemaGetResultSchema(OpenAPISchema):
    """Result schema for schema get request."""

    schema = fields.Nested(SchemaSchema())


class SchemasCreatedResultSchema(OpenAPISchema):
    """Result schema for a schemas-created request."""

    schema_ids = fields.List(
        fields.Str(description="Schema identifiers", **INDY_SCHEMA_ID)
    )


class SchemaIdMatchInfoSchema(OpenAPISchema):
    """Path parameters and validators for request taking schema id."""

    schema_id = fields.Str(
        description="Schema identifier",
        required=True,
        validate=Regexp(rf"^[1-9][0-9]*|[{B58}]{{21,22}}:2:.+:[0-9.]+$"),
        example=INDY_SCHEMA_ID["example"],
    )


class AutoEndorseOptionSchema(OpenAPISchema):
    """Class for user to input whether to auto-endorse the transaction or not."""

    auto_endorse = fields.Boolean(
        description="Auto-endorse Transaction",
        required=False,
    )


class EndorserDIDOptionSchema(OpenAPISchema):
    """Class for user to input the DID associated with the requested endorser."""

    endorser_did = fields.Str(
        description="Endorser DID",
        required=False,
    )


@docs(tags=["schema"], summary="Sends a schema to the ledger")
@request_schema(SchemaSendRequestSchema())
@querystring_schema(AutoEndorseOptionSchema())
@querystring_schema(EndorserDIDOptionSchema())
@response_schema(TxnOrSchemaSendResultSchema(), 200, description="")
async def schemas_send_schema(request: web.BaseRequest):
    """
    Request handler for sending a credential offer.

    Args:
        request: aiohttp request object

    Returns:
        The schema id sent

    """
    context: AdminRequestContext = request["context"]
    auto_endorse = json.loads(request.query.get("auto_endorse", "true"))
    endorser_did = request.query.get("endorser_did", None)

    body = await request.json()

    schema_name = body.get("schema_name")
    schema_version = body.get("schema_version")
    attributes = body.get("attributes")

    ledger = context.inject(BaseLedger, required=False)
    if not ledger:
        reason = "No ledger available"
        if not context.settings.get_value("wallet.type"):
            reason += ": missing wallet-type?"
        raise web.HTTPForbidden(reason=reason)

    issuer = context.inject(IndyIssuer)
    async with ledger:
        try:
            # if not auto_endorse, then the returned "schema_def" is actually
            # the signed transaction
            schema_id, schema_def = await shield(
                ledger.create_and_send_schema(
                    issuer,
                    schema_name,
                    schema_version,
                    attributes,
                    write_ledger=auto_endorse,
                    endorser_did=endorser_did,
                )
            )
        except (IndyIssuerError, LedgerError) as err:
            raise web.HTTPBadRequest(reason=err.roll_up) from err

    if auto_endorse:
        return web.json_response(
            {"sent": {"schema_id": schema_id, "schema": schema_def}}
        )
    else:
        session = await context.session()

        transaction_mgr = TransactionManager(session)
        try:
            transaction = await transaction_mgr.create_record(
                messages_attach=schema_def["signed_txn"],
                expires_time="1597708800",
            )
        except StorageError as err:
            raise web.HTTPBadRequest(reason=err.roll_up) from err

        return web.json_response({"txn": transaction.serialize()})


@docs(
    tags=["schema"],
    summary="Search for matching schema that agent originated",
)
@querystring_schema(SchemaQueryStringSchema())
@response_schema(SchemasCreatedResultSchema(), 200, description="")
async def schemas_created(request: web.BaseRequest):
    """
    Request handler for retrieving schemas that current agent created.

    Args:
        request: aiohttp request object

    Returns:
        The identifiers of matching schemas

    """
    context: AdminRequestContext = request["context"]

    session = await context.session()
    storage = session.inject(BaseStorage)
    found = await storage.find_all_records(
        type_filter=SCHEMA_SENT_RECORD_TYPE,
        tag_query={
            tag: request.query[tag] for tag in SCHEMA_TAGS if tag in request.query
        },
    )

    return web.json_response({"schema_ids": [record.value for record in found]})


@docs(tags=["schema"], summary="Gets a schema from the ledger")
@match_info_schema(SchemaIdMatchInfoSchema())
@response_schema(SchemaGetResultSchema(), 200, description="")
async def schemas_get_schema(request: web.BaseRequest):
    """
    Request handler for sending a credential offer.

    Args:
        request: aiohttp request object

    Returns:
        The schema details.

    """
    context: AdminRequestContext = request["context"]

    schema_id = request.match_info["schema_id"]

    ledger = context.inject(BaseLedger, required=False)
    if not ledger:
        reason = "No ledger available"
        if not context.settings.get_value("wallet.type"):
            reason += ": missing wallet-type?"
        raise web.HTTPForbidden(reason=reason)

    async with ledger:
        try:
            schema = await ledger.get_schema(schema_id)
        except LedgerError as err:
            raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({"schema": schema})


async def register(app: web.Application):
    """Register routes."""
    app.add_routes(
        [
            web.post("/schemas", schemas_send_schema),
            web.get("/schemas/created", schemas_created, allow_head=False),
            web.get("/schemas/{schema_id}", schemas_get_schema, allow_head=False),
        ]
    )


def post_process_routes(app: web.Application):
    """Amend swagger API."""

    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []
    app._state["swagger_dict"]["tags"].append(
        {
            "name": "schema",
            "description": "Schema operations",
            "externalDocs": {
                "description": "Specification",
                "url": (
                    "https://github.com/hyperledger/indy-node/blob/master/"
                    "design/anoncreds.md#schema"
                ),
            },
        }
    )
