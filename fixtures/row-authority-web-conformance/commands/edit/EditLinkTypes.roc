import pf.Ref
import pf.RowVersion
import pf.Text
import Title
import Models

EditLinkTypes :: [].{
	Input := { link_id : Ref(Models.Link), expected_version : RowVersion, title : Text(Title) }
}
