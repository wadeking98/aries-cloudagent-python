"""Test Problem Report Handler."""
import pytest

from asynctest import mock as async_mock

from ......connections.models import connection_target
from ......connections.models.conn_record import ConnRecord
from ......connections.models.diddoc import DIDDoc, PublicKey, PublicKeyType, Service
from ......core.profile import ProfileSession
from ......messaging.request_context import RequestContext
from ......messaging.responder import MockResponder
from ......storage.base import BaseStorage
from ......storage.error import StorageNotFoundError
from ......transport.inbound.receipt import MessageReceipt

from ...handlers import problem_report_handler as handler
from ...manager import OutOfBandManagerError, OutOfBandManager
from ...messages.problem_report import ProblemReport, ProblemReportReason


@pytest.fixture()
async def request_context() -> RequestContext:
    ctx = RequestContext.test_context()
    ctx.message_receipt = MessageReceipt()
    yield ctx


@pytest.fixture()
async def connection_record(request_context, session) -> ConnRecord:
    record = ConnRecord()
    request_context.connection_record = record
    await record.save(session)
    yield record


@pytest.fixture()
async def session(request_context) -> ProfileSession:
    yield await request_context.session()


class TestProblemReportHandler:
    @pytest.mark.asyncio
    @async_mock.patch.object(handler, "OutOfBandManager")
    async def test_called(self, mock_oob_mgr, request_context, connection_record):
        mock_oob_mgr.return_value.receive_problem_report = async_mock.CoroutineMock()
        request_context.message = ProblemReport(
            problem_code=ProblemReportReason.NO_EXISTING_CONNECTION.value
        )
        handler_inst = handler.OOBProblemReportMessageHandler()
        responder = MockResponder()
        await handler_inst.handle(context=request_context, responder=responder)
        mock_oob_mgr.return_value.receive_problem_report.assert_called_once_with(
            problem_report=request_context.message,
            receipt=request_context.message_receipt,
            conn_record=connection_record,
        )

    @pytest.mark.asyncio
    @async_mock.patch.object(handler, "OutOfBandManager")
    async def test_exception(self, mock_oob_mgr, request_context, connection_record):
        mock_oob_mgr.return_value.receive_problem_report = async_mock.CoroutineMock()
        mock_oob_mgr.return_value.receive_problem_report.side_effect = (
            OutOfBandManagerError("error")
        )
        request_context.message = ProblemReport(
            problem_code=ProblemReportReason.EXISTING_CONNECTION_NOT_ACTIVE.value
        )
        handler_inst = handler.OOBProblemReportMessageHandler()
        responder = MockResponder()
        await handler_inst.handle(context=request_context, responder=responder)
        assert mock_oob_mgr.return_value._logger.exception.called_once_("error")
