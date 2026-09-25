//! Opt-in, reproducible comparison using two admitted CI Status artifacts.
use anyhow::{Context, Result, ensure};
use day2::{
    development,
    store::{Fault, Runtime},
};
use serde_json::{Value, json};
use std::{path::Path, time::Instant};

const NOW: i64 = 1_790_208_000;

fn seed(runtime: &Runtime, rollups: bool) -> Result<()> {
    let mut db = rusqlite::Connection::open(runtime.db())?;
    let tx = db.transaction()?;
    let id = "unhex('00000000000070008000' || printf('%012x',n))";
    // Same 30-day, 20-repository facts in both versions. No production data.
    tx.execute_batch(&format!("WITH RECURSIVE seq(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM seq WHERE n<10060)
        INSERT INTO workflow_runs(id,version,created_at,owner,repo,repo_group,run_id,run_attempt,workflow_name,workflow_type,event_name,status,conclusion,created_time,html_url)
        SELECT {id},1,0,'wonderlydotcom','repo-'||(n%20),'group-'||(n%20),n,1,'Deploy',CASE WHEN n%3=0 THEN 'build' ELSE 'deploy' END,'push','completed',CASE WHEN n%4<2 THEN 'failure' ELSE 'success' END,{NOW}-((n/20)%30)*86400,'https://example.com/run' FROM seq;
        WITH RECURSIVE seq(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM seq WHERE n<3000)
        INSERT INTO job_failures(id,version,created_at,owner,repo,repo_group,job_id,run_id,run_attempt,failure_category,failure_signature_id,created_time)
        SELECT {id},1,0,'wonderlydotcom','repo-'||(n%20),'group-'||(n%20),n,n,1,CASE WHEN n%3=0 THEN 'test_failure' ELSE 'infra_runner_shutdown' END,'signature',{NOW}-((n/20)%30)*86400 FROM seq;
        UPDATE job_failures SET failure_category='test_failure' WHERE job_id%10=0;
        WITH RECURSIVE seq(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM seq WHERE n<1000)
        INSERT INTO webhook_deliveries(id,version,created_at,delivery_id,event_name,action,repo,result,received_at)
        SELECT {id},1,0,'delivery-'||n,'pull_request','dequeued','repo-'||(n%20),CASE WHEN n%3=0 THEN 'ignored' ELSE 'processed' END,{NOW}-((n/20)%30)*86400 FROM seq;"))?;
    if rollups {
        tx.execute_batch(&format!("INSERT INTO policy_bot_events(id,version,created_at,day,count) VALUES(unhex('00000000000070008000000000000001'),1,0,{NOW},7)"))?;
    } else {
        tx.execute_batch(&format!("INSERT INTO daily_metrics(id,version,created_at,day,repo,repo_group,metric,value)
            SELECT unhex('00000000000070008000'||printf('%012x',row_number() OVER ())),1,0,* FROM (
                SELECT created_time,repo,min(repo_group),'deploy_failures',count(*) FROM workflow_runs WHERE workflow_type='deploy' AND conclusion='failure' GROUP BY created_time,repo
                UNION ALL SELECT created_time,repo,min(repo_group),'infra_failures',count(*) FROM job_failures WHERE failure_category='infra_runner_shutdown' GROUP BY created_time,repo
                UNION ALL SELECT received_at,repo,repo,'merge_queue_boots',count(*) FROM webhook_deliveries WHERE result='processed' GROUP BY received_at,repo
                UNION ALL SELECT {NOW},'policy-bot','policy-bot','policy_bot_undelivered',7
            );"))?;
    }
    tx.commit()?;
    for rollup in &runtime.artifact().contract().schema.rollups {
        ensure!(rollup.mismatches(&db)? == 0, "independent recount mismatch");
    }
    Ok(())
}

fn invoke(runtime: &Runtime, operation: &str, id: &str, input: &Value) -> Result<(Value, f64)> {
    let start = Instant::now();
    let output = runtime.invoke(
        &format!("ci_status.{operation}"),
        development::ACTOR,
        id,
        input,
        NOW,
        Fault::None,
    )?;
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    ensure!(output.status == "success", "{output:?}");
    Ok((output.result, elapsed))
}

#[test]
#[ignore = "requires CI_STATUS_BASELINE_ARTIFACT and CI_STATUS_ROLLUP_ARTIFACT"]
fn compare_scorecard_and_recording_on_identical_facts() -> Result<()> {
    let baseline = std::env::var("CI_STATUS_BASELINE_ARTIFACT").context("baseline artifact")?;
    let rollup = std::env::var("CI_STATUS_ROLLUP_ARTIFACT").context("rollup artifact")?;
    let dir = tempfile::tempdir()?.keep();
    println!("benchmark evidence: {}", dir.display());
    development::verify(Path::new(&rollup), &dir.join("verification"), 42173, 16)?;
    let old = development::create(Path::new(&baseline), &dir.join("old"), None)?;
    let new = development::create(Path::new(&rollup), &dir.join("new"), None)?;
    seed(&old, false)?;
    seed(&new, true)?;
    for days in [7, 30, 90] {
        let mut samples = [Vec::new(), Vec::new()];
        for repetition in 0..12 {
            let id = format!("score-{days}-{repetition}");
            let (a, ta) = invoke(&old, "scorecard", &id, &json!({"window_days":days}))?;
            let (b, tb) = invoke(&new, "scorecard", &id, &json!({"window_days":days}))?;
            assert_eq!(a, b, "{days}-day scorecard");
            if repetition > 1 {
                samples[0].push(ta);
                samples[1].push(tb);
            }
        }
        for (name, mut times) in ["manual", "rollup"].into_iter().zip(samples) {
            times.sort_by(f64::total_cmp);
            println!(
                "scorecard {name} days={days} median_ms={:.3} min_ms={:.3} max_ms={:.3}",
                times[5], times[0], times[9]
            );
        }
    }
    for (name, runtime) in [("manual", &old), ("rollup", &new)] {
        let db = rusqlite::Connection::open(runtime.db())?;
        let tables = if name == "manual" {
            vec!["daily_metrics".to_owned()]
        } else {
            runtime
                .artifact()
                .contract()
                .schema
                .rollups
                .iter()
                .map(|r| r.table())
                .collect()
        };
        for table in tables {
            let count: i64 =
                db.query_row(&format!("SELECT count(*) FROM \"{table}\""), [], |r| {
                    r.get(0)
                })?;
            println!("cells {name} {table}={count}");
        }
    }
    let mut recent = [Vec::new(), Vec::new()];
    for n in 0..12 {
        let input = json!({"window":"30d","repo_group":"","repo":"","after":"","limit":100});
        let (mut a, ta) = invoke(&old, "recent_runs", &format!("recent-{n}"), &input)?;
        let (mut b, tb) = invoke(&new, "recent_runs", &format!("recent-{n}"), &input)?;
        a.as_object_mut().unwrap().remove("next_after");
        b.as_object_mut().unwrap().remove("next_after");
        assert_eq!(a, b);
        if n > 1 {
            recent[0].push(ta);
            recent[1].push(tb);
        }
    }
    for (name, mut times) in ["manual", "rollup"].into_iter().zip(recent) {
        times.sort_by(f64::total_cmp);
        println!("recent_runs {name} median_ms={:.3}", times[5]);
    }
    for (name, runtime) in [("manual", &old), ("rollup", &new)] {
        let mut times = Vec::new();
        for n in 0..30 {
            let input = json!({"owner":"wonderlydotcom","repo":"repo-1","repo_group":"group-1","run_id":10061+n,"run_attempt":1,"workflow_name":"Deploy","workflow_type":"deploy","event_name":"push","status":"completed","conclusion":"failure","created_at":NOW,"html_url":"https://example.com/run"});
            let (_, elapsed) = invoke(runtime, "record_run", &format!("record-{n}"), &input)?;
            times.push(elapsed);
        }
        times.sort_by(f64::total_cmp);
        println!(
            "record_run {name} median_ms={:.3} min_ms={:.3} max_ms={:.3}",
            times[15], times[0], times[29]
        );
        for rollup in &runtime.artifact().contract().schema.rollups {
            ensure!(
                rollup.mismatches(&rusqlite::Connection::open(runtime.db())?)? == 0,
                "recount mismatch after commands"
            );
        }
    }
    Ok(())
}
