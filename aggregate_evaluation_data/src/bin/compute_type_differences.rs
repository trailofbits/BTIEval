use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use aggregate_evaluation_data::{ComparisonSummary, EvaluatedVariable};
use binary_type_inference::constraints::TypeVariable;
use binary_type_inference::solver::type_sketch;
use binary_type_inference::util;
use binary_type_inference::{
    constraints::{DerivedTypeVar, FieldLabel},
    graph_algos::mapping_graph::MappingGraph,
    inference_job::{InferenceJob, JobDefinition, JsonDef, ProtobufDef},
    solver::{
        type_lattice::CustomLatticeElement,
        type_sketch::{LatticeBounds, SketchBuilder},
    },
};

use binary_type_inference::constraint_generation;

use clap::{App, Arg};

pub fn immutably_push<P>(pb: &PathBuf, new_path: P) -> PathBuf
where
    P: AsRef<Path>,
{
    let mut npath = pb.clone();
    npath.push(new_path);
    npath
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let matches = App::new("binary_to_types")
        .arg(Arg::with_name("input_bin").required(true).index(1))
        .arg(Arg::with_name("input_json").required(true).index(2))
        .arg(Arg::with_name("lattice_json").required(true))
        .arg(Arg::with_name("additional_constraints_file").required(true))
        .arg(Arg::with_name("interesting_tids").required(true))
        .arg(Arg::with_name("dwarf_constraints").required(true))
        .arg(Arg::with_name("dwarf_lattice").required(true))
        .arg(
            Arg::with_name("human_readable_input")
                .long("human_readable_input")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("human_readable_output")
                .long("human_readable_output")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("out")
                .long("out")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("debug_out_dir")
                .long("debug_out_dir")
                .required(false)
                .takes_value(true),
        )
        .get_matches();

    let input_bin = matches.value_of("input_bin").unwrap();
    let input_json = matches.value_of("input_json").unwrap();
    let lattice_json = matches.value_of("lattice_json").unwrap();
    let tids_file = matches.value_of("interesting_tids").unwrap();
    let out_file = matches.value_of("out").unwrap();
    let additional_constraints_file = matches.value_of("additional_constraints_file").unwrap();

    let job_def = JobDefinition {
        binary_path: input_bin.to_owned(),
        ir_json_path: input_json.to_owned(),
        lattice_json: lattice_json.to_owned(),
        interesting_tids: tids_file.to_owned(),
        additional_constraints_file: additional_constraints_file.to_owned(),
    };

    let dwarf_lattice_def = InferenceJob::parse_lattice_json_to_lattice_def(
        matches.value_of("dwarf_lattice").unwrap(),
    )?;

    let dbg_dir = matches.value_of("debug_out_dir").map(|x| x.to_owned());
    let mut if_job = if matches.is_present("human_readable_input") {
        InferenceJob::parse::<JsonDef>(&job_def, dbg_dir, vec![dwarf_lattice_def])
    } else {
        InferenceJob::parse::<ProtobufDef>(&job_def, dbg_dir, vec![dwarf_lattice_def])
    }?;

    let universal_inferred_supergraph = if_job.infer_labeled_graph()?;

    let dwarf_sketche_file = matches.value_of("dwarf_constraints").unwrap();

    let dwarf_constraints = if matches.is_present("human_readable_input") {
        InferenceJob::parse_additional_constraints::<JsonDef>(&dwarf_sketche_file)
    } else {
        InferenceJob::parse_additional_constraints::<ProtobufDef>(&dwarf_sketche_file)
    }?;
    let lattice_elems: HashSet<TypeVariable> = if_job.get_lattice_elems().collect();

    let add_new_var = |dtv: &DerivedTypeVar,
                       mpgrph: &mut MappingGraph<
        LatticeBounds<CustomLatticeElement>,
        DerivedTypeVar,
        FieldLabel,
    >| {
        type_sketch::insert_dtv(if_job.get_lattice(), mpgrph, dtv.clone());
        Ok(())
    };

    let skb = SketchBuilder::new(
        if_job.get_lattice(),
        &lattice_elems,
        &add_new_var,
        if_job.get_file_logger(),
    );
    let dwarf_sketches = dwarf_constraints
        .into_iter()
        .map(|(tid, constraint_set)| {
            skb.build_and_label_constraints(&util::constraint_set_to_subtys(&constraint_set))
                .and_then(|skg| {
                    let mut sketches = skg.get_representing_sketch(DerivedTypeVar::new(
                        constraint_generation::tid_to_tvar(&tid),
                    ));

                    if sketches.len() != 1 {
                        Err(anyhow::anyhow!(
                            "Should not have multiple sketches for repr tid"
                        ))
                    } else {
                        Ok(sketches.remove(0).1)
                    }
                })
                .map(|sketch| (tid, sketch))
        })
        .collect::<anyhow::Result<BTreeMap<_, _>>>()?;
    let test_pairs = if_job
        .get_interesting_tids()
        .into_iter()
        .filter_map(|target_tid| {
            dwarf_sketches.get(target_tid).and_then(|dwarf_sketch| {
                let sk = universal_inferred_supergraph.get_representing_sketch(
                    DerivedTypeVar::new(constraint_generation::tid_to_tvar(&target_tid)),
                );

                sk.into_iter()
                    .next()
                    .map(|(_, actual_sketch)| (target_tid, dwarf_sketch, actual_sketch))
            })
        });

    let comparisons: Vec<ComparisonSummary> = test_pairs
        .map(|(curr_tid, expected_type, actual_type)| {
            aggregate_evaluation_data::summarize_comparison(
                curr_tid,
                &aggregate_evaluation_data::compare_variable(expected_type, &actual_type),
            )
        })
        .collect();

    let output_file = std::fs::File::create(out_file)?;

    serde_json::to_writer(output_file, &comparisons)?;
    Ok(())
}
