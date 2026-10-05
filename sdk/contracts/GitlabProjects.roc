import ConnectionAccess

# Semantic intent only; reviewed host profiles own scopes and account evidence.
GitlabProjects :: [].{
	read_projects : ConnectionAccess
	read_projects = ConnectionAccess.define("gitlab_projects", ["list_projects"])
}
