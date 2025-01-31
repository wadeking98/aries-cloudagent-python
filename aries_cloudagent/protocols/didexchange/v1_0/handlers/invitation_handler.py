"""Connect invitation handler under RFC 23 (DID exchange)."""

from .....messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    RequestContext,
)

from ....out_of_band.v1_0.messages.invitation import InvitationMessage
from ....problem_report.v1_0.message import ProblemReport

from ..messages.problem_report_reason import ProblemReportReason


class InvitationHandler(BaseHandler):
    """Handler class for connection invitation message under RFC 23 (DID exchange)."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Handle connection invitation under RFC 23 (DID exchange).

        Args:
            context: Request context
            responder: Responder callback
        """

        self._logger.debug(f"InvitationHandler called with context {context}")
        assert isinstance(context.message, InvitationMessage)

        explain_ltxt = (
            "Out-of-band invitations for DID exchange "
            "cannot be submitted via agent messaging"
        )
        report = ProblemReport(
            explain_ltxt=explain_ltxt,
            problem_items=[
                {ProblemReportReason.INVITATION_NOT_ACCEPTED.value: explain_ltxt}
            ],
        )
        # client likely needs to be using direct responses to receive the problem report
        await responder.send_reply(report)
