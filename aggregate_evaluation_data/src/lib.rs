use std::collections::BTreeSet;
use std::fmt::Display;

use alga::general::{AbstractMagma, Additive, Lattice};
use binary_type_inference::constraints::FieldLabel;
use binary_type_inference::graph_algos::{explore_paths, find_node};
use binary_type_inference::solver::type_sketch::SketchLabelElement;
use binary_type_inference::solver::type_sketch::{LatticeBounds, Sketch};
use cwe_checker_lib::intermediate_representation::Tid;
use petgraph::graph::NodeIndex;
use serde::{Deserialize, Serialize};

/// A node comparison represents the comparison of two primitive type labels that are considered equivalent
/// since they are reached by the same path.
#[derive(Deserialize, Serialize)]
pub struct NodeComparison<U: Clone + Lattice + Display> {
    expected_type_bounds: LatticeBounds<U>,
    actual_type_bounds: LatticeBounds<U>,
    path: Vec<FieldLabel>,
}

/// Results from comparing a type variable's sketch to it's actual type
#[derive(Serialize, Deserialize)]
pub struct EvaluatedVariable<U: Clone + Lattice + Display> {
    over_precise_language: Option<Sketch<LatticeBounds<U>>>,
    missing_language: Option<Sketch<LatticeBounds<U>>>,
    node_labels_to_compare: Vec<NodeComparison<U>>,
}

fn get_comparisons_between<'a, U>(
    expected_type: &'a Sketch<U>,
    actual_type: &'a Sketch<U>,
) -> impl Iterator<Item = (NodeIndex, NodeIndex, Vec<FieldLabel>)> + 'a
where
    U: SketchLabelElement,
{
    let target_graph = actual_type.get_graph().get_graph();
    explore_paths(target_graph, actual_type.get_entry()).filter_map(|(tgt_path, act_nd)| {
        let reaching_path: Vec<FieldLabel> = tgt_path
            .iter()
            .map(|x| {
                actual_type
                    .get_graph()
                    .get_graph()
                    .edge_weight(*x)
                    .expect("Every reached edge should be in the graph")
                    .clone()
            })
            .collect::<Vec<_>>();

        let corresponding = find_node(
            expected_type.get_graph().get_graph(),
            expected_type.get_entry(),
            reaching_path.iter(),
        );

        corresponding.map(|dst_nd| (dst_nd, act_nd, reaching_path))
    })
}

fn get_nodes_to_compare<U>(
    expected_type: &Sketch<U>,
    actual_type: &Sketch<U>,
) -> Vec<(NodeIndex, NodeIndex, Vec<FieldLabel>)>
where
    U: SketchLabelElement,
{
    let orig_compares = get_comparisons_between(expected_type, actual_type).chain(
        get_comparisons_between(actual_type, expected_type).map(|(x, y, rpth)| (y, x, rpth)),
    );

    let mut seen = BTreeSet::new();
    let mut tot = Vec::new();
    for (end, and, rpth) in orig_compares {
        if !seen.contains(&(end, and)) {
            seen.insert((end, and));
            tot.push((end, and, rpth));
        }
    }

    tot
}

fn generate_node_comparisons<U>(
    expected_type: &Sketch<LatticeBounds<U>>,
    actual_type: &Sketch<LatticeBounds<U>>,
) -> Vec<NodeComparison<U>>
where
    U: Lattice + Clone + Display,
{
    get_nodes_to_compare(expected_type, actual_type)
        .into_iter()
        .map(|(e_nd, a_nd, rpth)| {
            let elb = expected_type
                .get_graph()
                .get_graph()
                .node_weight(e_nd)
                .expect("found node should exist in graph");
            let alb = actual_type
                .get_graph()
                .get_graph()
                .node_weight(a_nd)
                .expect("found node should exist in graph");
            NodeComparison {
                expected_type_bounds: elb.clone(),
                actual_type_bounds: alb.clone(),
                path: rpth,
            }
        })
        .collect::<Vec<_>>()
}

pub fn compare_variable<U>(
    expected_type: &Sketch<LatticeBounds<U>>,
    actual_type: &Sketch<LatticeBounds<U>>,
) -> EvaluatedVariable<U>
where
    U: Lattice + Clone + Display,
{
    let maybe_overrefined_language = actual_type.difference(expected_type);
    let maybe_missing_language = expected_type.difference(actual_type);

    let overrefined_language = if !maybe_overrefined_language.empty_language() {
        Some(maybe_overrefined_language)
    } else {
        None
    };

    let missing_language = if maybe_missing_language.empty_language() {
        Some(maybe_missing_language)
    } else {
        None
    };

    EvaluatedVariable {
        over_precise_language: overrefined_language,
        missing_language: missing_language,
        node_labels_to_compare: generate_node_comparisons(expected_type, actual_type),
    }
}

#[derive(Deserialize, Serialize)]
pub enum LanguageComparison {
    Incomparable,
    Underprecise,
    Overprecise,
    ExactMatch,
}

/// Summarizes a comparison into aggregateable facts
#[derive(Deserialize, Serialize)]
pub struct ComparisonSummary {
    type_name: String,
    languague_result: LanguageComparison,
    number_of_unsound_node_labels: usize,
    number_of_nodes_compared: usize,
}

pub fn summarize_comparison<U>(curr_tid: &Tid, var: &EvaluatedVariable<U>) -> ComparisonSummary
where
    U: Lattice + Clone + Display,
{
    ComparisonSummary {
        type_name: curr_tid.get_str_repr().to_owned(),
        languague_result: match (
            var.missing_language.is_some(),
            var.over_precise_language.is_some(),
        ) {
            (true, true) => LanguageComparison::Incomparable,
            (true, false) => LanguageComparison::Underprecise,
            (false, true) => LanguageComparison::Overprecise,
            (false, false) => LanguageComparison::ExactMatch,
        },
        number_of_unsound_node_labels: var
            .node_labels_to_compare
            .iter()
            .filter(|node_comp| {
                node_comp
                    .expected_type_bounds
                    .get_lower()
                    .lt(node_comp.actual_type_bounds.get_lower())
                    || node_comp
                        .expected_type_bounds
                        .get_upper()
                        .gt(node_comp.actual_type_bounds.get_upper())
            })
            .count(),
        number_of_nodes_compared: var.node_labels_to_compare.len(),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
