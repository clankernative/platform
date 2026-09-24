import pf.Ref
import pf.RowVersion
import pf.Text
import Document
import Models

ReviseReportTypes :: [].{
	Input := { report_id : Ref(Models.Report), expected_version : RowVersion, text : Text(Document) }
}
