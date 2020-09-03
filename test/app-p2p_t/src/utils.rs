use dotenv::dotenv;
use futures::{
    future::{BoxFuture, FutureExt},
    stream::{FuturesUnordered, StreamExt},
};
use std::env;
use transmission_rpc::types::{BasicAuth, Result, RpcResponse};
use transmission_rpc::types::{Id, Nothing, TorrentAction};
use transmission_rpc::types::{Torrent, TorrentGetField, Torrents};
use transmission_rpc::types::{TorrentAddArgs, TorrentAdded};
use transmission_rpc::TransClient;

pub fn create_transmission_client() -> Result<TransClient> {
    dotenv().ok();
    // env_logger::init();

    // setup session
    let url: String = env::var("TURL")?;
    let basic_auth = BasicAuth {
        user: env::var("TUSER")?,
        password: env::var("TPWD")?,
    };
    let client = TransClient::with_auth(&url, basic_auth);
    Ok(client)
}

pub async fn add_all_torrents(p2p_param: usize, mut workload: Vec<String>, torrents_dir: String) -> Result<()> {
    let client = create_transmission_client().unwrap();
    let mut futures: FuturesUnordered<BoxFuture<Result<RpcResponse<TorrentAdded>>>> = FuturesUnordered::new();

    for (pos, t) in workload.iter().enumerate() {
        println!("Torrent at position {}: {:?}", pos, t);
        if pos >= p2p_param {
            println!("exiting with {}", pos);
            break;
        }
        // add torrent
        let add: TorrentAddArgs = TorrentAddArgs {
            filename: Some(torrents_dir.clone() + &t.to_string()),
            ..TorrentAddArgs::default()
        };

        futures.push(Box::pin(client.torrent_add(add)));
    }

    while let Some(result) = futures.next().await {
        match result {
            Ok(_) => println!("ok"),
            Err(e) => eprintln!("err {}", e),
        }
    }

    Ok(())
}

pub async fn run_all_torrents() -> Result<()> {
    let client = create_transmission_client().unwrap();
    let res: RpcResponse<Torrents<Torrent>> = client
        .torrent_get(Some(vec![TorrentGetField::Id, TorrentGetField::Name]), None)
        .await?;
    let ids: Vec<Id> = res
        .arguments
        .torrents
        .iter()
        .map(|it| Id::Id(*it.id.as_ref().unwrap()))
        .collect();

    let res1: RpcResponse<Nothing> = client.torrent_action(TorrentAction::Start, ids).await?;
    println!("Start result: {:?}", &res1.is_ok());

    Ok(())
}
