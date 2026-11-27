import Configure
import SettingsInvariant
import SubmitRequest
import Triage
import MyRequests
import ReviewQueue
import Proposal
import IntakeRoutes
import RequestInvariants
import RevisionInvariants
import SaveRevision
import ReadRevision
import Demo

App :: [].{
	definition = {
		namespace: "vendorintake",
		operations: {
			configure: Configure.definition,
			my_requests: MyRequests.definition,
			review_queue: ReviewQueue.definition,
			proposal: Proposal.definition,
			submit_request: SubmitRequest.definition,
			triage: Triage.definition,
			revision: ReadRevision.definition,
			save_revision: SaveRevision.definition,
		},
		pages: {
			intake: IntakeRoutes.intake.register(),
			review: IntakeRoutes.review.register(),
			proposal: IntakeRoutes.proposal.register(),
		},
		properties: {
			settings: SettingsInvariant.settings,
			requests: RequestInvariants.requests,
			revisions: RevisionInvariants.revisions,
		},
		errors: {
			invalid_settings: Configure.invalid_settings,
			frozen_settings: Configure.frozen_settings,
			membership_required: SubmitRequest.membership_required,
			invalid_proposal: SubmitRequest.invalid_proposal,
			reviewer_required: Triage.reviewer_required,
			unavailable_request: Triage.unavailable_request,
			invalid_review: Triage.invalid_review,
			invalid_html: SaveRevision.invalid_html,
			missing_revision: ReadRevision.missing_revision,
		},
		examples: [Demo.definition],
		presentation: { stylesheet: "", script: "intake.js" },
	}
}
