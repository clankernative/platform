import pf.Env
import pf.Path
import pf.OsStr
import Names
import Problem

## Local metadata reads. The stat/read checks do not claim atomic filesystem
## admission; callers validate the returned content independently.
Metadata :: [].{
	absolute! : Names.LocalPath => Try(Names.LocalPath, Problem)
	absolute! = |path| {
		raw_path = path.to_str()
		if raw_path.starts_with("/") {
			return Ok(path)
		}
		cwd = Env.cwd!().map_err(|_| Problem.ContextUnavailable)?
		cwd_text = OsStr.to_str_try(Path.to_os_str(cwd)).map_err(|_| Problem.ContextUnavailable)?
		if !cwd_text.starts_with("/") {
			return Err(Problem.ContextUnavailable)
		}
		Names.LocalPath.from_str("${cwd_text}/${raw_path}")
			.map_err(|_| Problem.InvalidContext("resolved path exceeds the path budget"))
	}

	read! : Names.LocalPath => Try(Str, Problem)
	read! = |path| {
		text = path.to_str()
		file_path = Path.utf8(text)
		regular = Path.is_file!(file_path).map_err(|_| Problem.MetadataUnreadable(text))?
		if !regular {
			return Err(Problem.MetadataUnreadable(text))
		}
		size = Path.size_in_bytes!(file_path).map_err(|_| Problem.MetadataUnreadable(text))?
		if size > 1_048_576 {
			return Err(Problem.MetadataTooLarge)
		}
		raw = Path.read_utf8!(file_path).map_err(|_| Problem.MetadataUnreadable(text))?
		if raw.count_utf8_bytes() > 1_048_576 {
			return Err(Problem.MetadataTooLarge)
		}
		Ok(raw)
	}
}
