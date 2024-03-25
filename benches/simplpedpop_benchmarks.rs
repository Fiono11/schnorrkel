use criterion::{criterion_group, criterion_main, Criterion};

mod simplpedpop_benches {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use criterion::BenchmarkId;
    use merlin::Transcript;
    use rand_core::OsRng;
    use schnorrkel::{
        identifier::Identifier,
        simplpedpop::{
            round1::{self, PrivateData, PrivateMessage, PublicData, PublicMessage},
            round2, round3, Parameters,
        },
    };

    fn generate_parameters(max_signers: u16, min_signers: u16) -> Vec<Parameters> {
        (1..=max_signers)
            .map(|i| {
                let own_identifier = i.try_into().expect("should be nonzero");

                let others_identifiers = (1..=max_signers)
                    .filter_map(|j| {
                        if j != i {
                            Some(j.try_into().expect("should be nonzero"))
                        } else {
                            None
                        }
                    })
                    .collect();

                Parameters::new(max_signers, min_signers, own_identifier, others_identifiers)
            })
            .collect()
    }

    fn round2(
        participants: u16,
        parameters_list: Vec<Parameters>,
        participants_round1_private_data: Vec<PrivateData>,
        participants_round1_public_data: Vec<PublicData>,
        participants_round1_public_messages: Vec<BTreeMap<Identifier, PublicMessage>>,
        participants_round1_private_messages: Vec<BTreeMap<Identifier, PrivateMessage>>,
    ) -> (
        Vec<round2::PublicData<Transcript>>,
        Vec<round2::PublicMessage>,
    ) {
        let mut participants_round2_public_data = Vec::new();
        let mut participants_round2_private_data = Vec::new();
        let mut participants_round2_public_messages = Vec::new();

        for i in 0..participants {
            let result = round2::run(
                &parameters_list[i as usize],
                participants_round1_private_data[i as usize].clone(),
                &participants_round1_public_data[i as usize].clone(),
                &participants_round1_public_messages[i as usize].clone(),
                participants_round1_private_messages[i as usize].clone(),
                Transcript::new(b"transcript"),
            )
            .expect("Round 2 should complete without errors!");

            participants_round2_public_data.push(result.0);
            participants_round2_private_data.push(result.1);
            participants_round2_public_messages.push(result.2);
        }

        (
            participants_round2_public_data,
            participants_round2_public_messages,
        )
    }

    fn round1(
        participants: u16,
        threshold: u16,
    ) -> (
        Vec<Parameters>,
        Vec<PrivateData>,
        Vec<PublicData>,
        Vec<BTreeMap<Identifier, PublicMessage>>,
        Vec<BTreeMap<Identifier, PrivateMessage>>,
        BTreeSet<Identifier>,
    ) {
        let parameters_list = generate_parameters(participants, threshold);

        let mut all_public_messages = Vec::new();
        let mut all_private_messages = Vec::new();
        let mut participants_round1_private_data = Vec::new();
        let mut participants_round1_public_data = Vec::new();
        let mut participants_round1_messages = Vec::new();

        for parameters in parameters_list.iter() {
            let (private_data, messages, public_data) =
                round1::run(parameters, OsRng).expect("Round 1 should complete without errors!");

            all_public_messages.push((
                parameters.own_identifier(),
                messages.public_message().clone(),
            ));
            all_private_messages.push((
                parameters.own_identifier(),
                messages.private_messages().clone(),
            ));
            participants_round1_messages.push(messages);
            participants_round1_private_data.push(private_data);
            participants_round1_public_data.push(public_data);
        }

        let mut participants_round1_public_messages: Vec<BTreeMap<Identifier, PublicMessage>> =
            Vec::new();
        let mut participants_round1_private_messages: Vec<BTreeMap<Identifier, PrivateMessage>> =
            Vec::new();

        let mut identifiers: BTreeSet<Identifier> = parameters_list[0]
            .others_identifiers()
            .iter()
            .copied()
            .collect();

        identifiers.insert(*parameters_list[0].own_identifier());

        for identifier in &identifiers {
            let mut all_public_msgs = BTreeMap::new();
            let mut received_private_msgs = BTreeMap::new();

            for i in 0..participants {
                all_public_msgs.insert(
                    *all_public_messages[i as usize].0,
                    all_public_messages[i as usize].1.clone(),
                );
            }

            participants_round1_public_messages.push(all_public_msgs);

            for i in 0..participants {
                if let Some(private_msg) = all_private_messages[i as usize].1.get(identifier) {
                    received_private_msgs
                        .insert(*all_private_messages[i as usize].0, private_msg.clone());
                }
            }

            participants_round1_private_messages.push(received_private_msgs);
        }

        for i in 0..participants {
            participants_round1_public_messages[i as usize]
                .remove(&parameters_list[i as usize].own_identifier());
        }

        (
            parameters_list,
            participants_round1_private_data,
            participants_round1_public_data,
            participants_round1_public_messages,
            participants_round1_private_messages,
            identifiers,
        )
    }

    fn benchmark_simplpedpop(c: &mut Criterion) {
        let mut group = c.benchmark_group("SimplPedPoP");

        group
            .sample_size(10)
            .warm_up_time(std::time::Duration::from_secs(2))
            .measurement_time(std::time::Duration::from_secs(30));

        for &n in [3, 10, 100].iter() {
            let participants = n;
            let threshold = (n * 2 + 2) / 3;
            let parameters_list = generate_parameters(participants, threshold);

            group.bench_function(BenchmarkId::new("round1", participants), |b| {
                b.iter(|| {
                    round1::run(&parameters_list[0], OsRng).unwrap();
                })
            });

            let (
                parameters_list,
                participants_round1_private_data,
                participants_round1_public_data,
                participants_round1_public_messages,
                participants_round1_private_messages,
                identifiers,
            ) = round1(participants, threshold);

            group.bench_function(BenchmarkId::new("round2", participants), |b| {
                b.iter(|| {
                    round2::run(
                        &parameters_list[0],
                        participants_round1_private_data[0].clone(),
                        &participants_round1_public_data[0].clone(),
                        &participants_round1_public_messages[0].clone(),
                        participants_round1_private_messages[0].clone(),
                        Transcript::new(b"transcript"),
                    )
                    .unwrap();
                })
            });

            let (participants_round2_public_data, participants_round2_public_messages) = round2(
                participants,
                parameters_list.clone(),
                participants_round1_private_data.clone(),
                participants_round1_public_data.clone(),
                participants_round1_public_messages.clone(),
                participants_round1_private_messages.clone(),
            );

            let identifiers_vec: Vec<Identifier> = identifiers.clone().iter().copied().collect();

            let received_round2_public_messages = participants_round2_public_messages
                .iter()
                .enumerate()
                .filter(|(index, _msg)| {
                    identifiers_vec[*index] != *parameters_list[0].own_identifier()
                })
                .map(|(index, msg)| (identifiers_vec[index], msg.clone()))
                .collect::<BTreeMap<Identifier, round2::PublicMessage>>();

            group.bench_function(BenchmarkId::new("round3", participants), |b| {
                b.iter(|| {
                    round3::run(
                        &parameters_list[0],
                        &received_round2_public_messages,
                        &participants_round2_public_data[0],
                        &participants_round1_public_data[0],
                        &participants_round1_public_messages[0],
                    )
                    .unwrap();
                })
            });
        }
        group.finish();
    }

    criterion_group! {
        name = simplpedpop_benches;
        config = Criterion::default();
        targets =
            benchmark_simplpedpop,
    }
}

criterion_main!(simplpedpop_benches::simplpedpop_benches);
