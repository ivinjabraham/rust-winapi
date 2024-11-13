/*
Copyright (C) 2024 Ivin Joel Abraham

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
use serde::{Deserialize, Serialize};
use serde_json::to_writer_pretty;
use serde_xml_rs::from_str;
use std::fs::File;
use std::io::{self, BufWriter};
use std::process::Command;
use sysinfo::{Pid, ProcessesToUpdate, System as SysSystem};
use win_event_log::prelude::*;

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct EventInfo {
    pub event_id: u32,
    pub provider_name: String,
    pub level: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct ProcessInfo {
    pid: i32,
    name: String,
    ports: Vec<u16>,
}

#[derive(Serialize, Deserialize, Debug)]
struct ProcessPortList {
    processes: Vec<ProcessInfo>,
}

// Struct to deserialize the XML data into
#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct Event {
    pub system: System,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct System {
    pub provider: Provider,
    #[serde(rename="EventID")]
    pub event_id: u32,
    pub level: u32,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct Provider {
    pub name: String,
}

fn save_events_to_file(events: Vec<EventInfo>, file_name: &str) -> io::Result<()> {
    let file = File::create(file_name)?;
    let writer = BufWriter::new(file);
    to_writer_pretty(writer, &events)?;
    Ok(())
}

fn get_netstat_output() -> Vec<String> {
    let output = Command::new("netstat")
        .arg("-no")
        .output()
        .expect("Failed to run netstat");

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| line.to_string())
        .collect()
}

fn parse_netstat_output(output: Vec<String>) -> Vec<(u16, i32)> {
    let mut process_ports = Vec::new();

    for line in output {
        if line.starts_with("Proto") || line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 5 {
            if let Some(port_str) = parts[1].split(':').last() {
                if let Ok(port) = port_str.parse::<u16>() {
                    if let Ok(pid) = parts[4].parse::<i32>() {
                        process_ports.push((port, pid));
                    }
                }
            }
        }
    }

    process_ports
}

fn match_processes_to_ports(
    mut system: SysSystem,
    process_ports: Vec<(u16, i32)>,
) -> Vec<ProcessInfo> {
    let mut process_info_list: Vec<ProcessInfo> = Vec::new();

    system.refresh_processes(ProcessesToUpdate::All, true);
    let processes = system.processes();

    for (port, pid) in process_ports {
        if let Some(process) = processes.get(&Pid::from_u32(pid.try_into().unwrap())) {
            if let Some(info) = process_info_list.iter_mut().find(|p| p.pid == pid) {
                info.ports.push(port);
            } else {
                process_info_list.push(ProcessInfo {
                    pid,
                    name: process.name().to_string_lossy().into_owned(),
                    ports: vec![port],
                });
            }
        }
    }

    process_info_list
}

fn save_process_info_to_file(process_info_list: Vec<ProcessInfo>, file_name: &str) {
    let file = File::create(file_name).expect("Unable to create file");
    let process_port_list = ProcessPortList {
        processes: process_info_list,
    };

    to_writer_pretty(file, &process_port_list).expect("Failed to write JSON to file");
}

fn fetch_and_parse_events(query: QueryList) -> Vec<EventInfo> {
    match WinEvents::get(query) {
        Ok(events) => {
            let mut extracted_events: Vec<EventInfo> = Vec::new();

            for event in events {
                let event_xml = event.to_string();
                match from_str::<Event>(&event_xml) {
                    Ok(parsed_event) => {
                        extracted_events.push(EventInfo {
                            event_id: parsed_event.system.event_id,
                            provider_name: parsed_event.system.provider.name,
                            level: parsed_event.system.level,
                        });
                    }
                    Err(e) => {
                        eprintln!("Error parsing event: {}", e);
                    }
                }
            }
            extracted_events
        }
        Err(e) => {
            eprintln!("Error fetching events: {}", e);
            Vec::new()
        }
    }
}

fn main() {
    // Exposed Ports Collector 
    let netstat_output = get_netstat_output();
    let process_ports = parse_netstat_output(netstat_output);

    let system = SysSystem::new_all();

    let process_info_list = match_processes_to_ports(system, process_ports);
    save_process_info_to_file(process_info_list, "process_ports.json");

    println!("Process and port data saved to 'process_ports.json'");

    // Event Logger
    let conditions = vec![Condition::filter(EventFilter::level(
        1,
        Comparison::GreaterThanOrEqual,
    ))];

    let query = QueryList::new()
        .with_query(
            Query::new()
                .item(
                    QueryItem::selector("Application".to_owned())
                        .system_conditions(Condition::or(conditions.clone()))
                        .build(),
                )
                .item(
                    QueryItem::selector("System".to_owned())
                        .system_conditions(Condition::or(conditions))
                        .build(),
                )
                .query(),
        )
        .build();

    let extracted_events = fetch_and_parse_events(query);

    if let Err(e) = save_events_to_file(extracted_events, "events.json") {
        eprintln!("Error saving events to file: {}", e);
    } else {
        println!("Events saved to 'events.json'");
    }
}