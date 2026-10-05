import pf.ConnectionRequirement
import pf.GitlabProjects

ProjectsConnection :: [].{
	requirement = ConnectionRequirement.for_current_human({
		id: "work_projects",
		revision: 1,
		access: GitlabProjects.read_projects,
		account: ConnectionRequirement.explicit_external_account,
		usage: "Read your work GitLab projects for the installation qualification canary.",
	})
}
