"""Handler for incoming forward invitation messages."""

from .....messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    HandlerException,
    RequestContext,
)

from ....connections.v1_0.manager import ConnectionManager, ConnectionManagerError
from ....problem_report.v1_0.message import ProblemReport

from ..messages.forward_invitation import ForwardInvitation


class ForwardInvitationHandler(BaseHandler):
    """Handler for incoming forward invitation messages."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """Message handler implementation."""
        self._logger.debug("ForwardInvitationHandler called with context %s", context)
        assert isinstance(context.message, ForwardInvitation)

        if not context.connection_ready:
            raise HandlerException(
                "No connection established for forward invitation message"
            )

        # Store invitation
        session = await context.session()
        connection_mgr = ConnectionManager(session)

        try:
            await connection_mgr.receive_invitation(context.message.invitation)
        except ConnectionManagerError as e:
            self._logger.exception("Error receiving forward connection invitation")
            await responder.send_reply(ProblemReport(explain_ltxt=e.message))
