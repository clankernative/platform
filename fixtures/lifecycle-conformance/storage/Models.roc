import pf.Ref
import pf.Text
import Title

Models :: [].{
	Parent := { title : Text(Title), owner : Str }

	Child := { title : Text(Title), parent_id : Ref(Parent), owner : Str }
}
