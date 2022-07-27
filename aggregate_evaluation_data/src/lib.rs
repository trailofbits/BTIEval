use std::collections::BTreeSet;
use std::fmt::Display;

use alga::general::{AbstractMagma, Additive, Lattice};
use binary_type_inference::constraints::FieldLabel;
use binary_type_inference::graph_algos::{explore_paths, find_node};
use binary_type_inference::solver::type_sketch::SketchLabelElement;
use binary_type_inference::solver::type_sketch::{LatticeBounds, Sketch};
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
    incorrect_node_labels: Vec<NodeComparison<U>>,
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

        corresponding.map(|dst_nd| (act_nd, dst_nd, reaching_path))
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
        incorrect_node_labels: generate_node_comparisons(expected_type, actual_type),
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
