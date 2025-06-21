use std::ffi::{OsStr, OsString};
use eframe::{egui, App, Frame};
use mach2::kern_return::KERN_SUCCESS;
use mach2::message::mach_msg_type_number_t;
use mach2::port::mach_port_t;
use mach2::traps::{mach_task_self, task_for_pid};
use mach2::vm::{mach_vm_read_overwrite, mach_vm_region};
use mach2::vm_prot::VM_PROT_READ;
use mach2::vm_region::{vm_region_basic_info, VM_REGION_BASIC_INFO_64};
use mach2::vm_types::{mach_vm_address_t, mach_vm_size_t, vm_address_t, vm_size_t};
use std::mem::{size_of_val, zeroed};
use std::time::Instant;
use egui::ScrollArea;
use sysinfo::System;

#[derive(Clone)]
struct MemoryRegion {
    start: u64,
    end: u64,
    size: usize,
    protection: u32,
}


fn get_task_for_pid(pid: i32) -> Option<mach_port_t> {
    let mut task: mach_port_t = 0;
    unsafe {
        if task_for_pid(mach_task_self(), pid, &mut task) == KERN_SUCCESS {
            Some(task)
        } else {
            None
        }
    }
}

fn get_readable_regions(task: mach_port_t) -> Vec<MemoryRegion> {
    let mut regions = Vec::new();
    unsafe {
        let mut address: vm_address_t = 1;
        let mut size: vm_size_t = 0;
        let mut info: vm_region_basic_info = zeroed();
        let mut info_count = size_of_val(&info) as mach_msg_type_number_t;
        let mut object_name: mach_port_t = 0;

        while mach_vm_region(
            task,
            &mut address as *mut _ as *mut u64,
            &mut size as *mut _ as *mut u64,
            VM_REGION_BASIC_INFO_64,
            &mut info as *mut _ as *mut i32,
            &mut info_count,
            &mut object_name,
        ) == KERN_SUCCESS
        {
            if info.protection & VM_PROT_READ != 0 {
                regions.push(MemoryRegion {
                    start: address as u64,
                    end: (address + size) as u64,
                    size: size as usize,
                    protection: info.protection as u32,
                });
            }
            address += size;
        }
    }
    regions
}

fn read_memory(task: mach_port_t, address: u64, size: usize) -> Option<Vec<u8>> {
    unsafe {
        let mut buffer = vec![0u8; size];
        let mut size_read: mach_vm_size_t = 0;
        let result = mach_vm_read_overwrite(
            task,
            address,
            size as mach_vm_size_t,
            buffer.as_mut_ptr() as mach_vm_address_t,
            &mut size_read,
        );
        if result == KERN_SUCCESS {
            buffer.truncate(size_read as usize);
            Some(buffer)
        } else {
            None
        }
    }
}

fn list_user_processes() -> Vec<(String, i32)> {
    let mut sys = System::new_all();
    sys.refresh_all();
    sys.processes()
        .iter()
        .map(|(&pid, process)| (process.name().to_owned().into_string().unwrap(), pid.as_u32() as i32))
        .collect()
}

const FLASH_MS: u64 = 300;

struct MemoryViewerApp {
    task: mach_port_t,
    regions: Vec<MemoryRegion>,
    selected_index: usize,
    buffer: Vec<u8>,
    last_buffer: Vec<u8>,
    last_update: Instant,
    refresh_ms: u64,
    pause: bool,
    filter_text: String,
    flash_bytes: Vec<Option<Instant>>,
    read_size: usize,
    process_list: Vec<(String, i32)>,
    selected_process_index: usize,
}

impl MemoryViewerApp {

    fn set_target_process(&mut self, idx: usize) {
        if idx >= self.process_list.len() {
            return;
        }
        self.selected_process_index = idx;
        let pid = self.process_list[idx].1;
        if let Some(task) = get_task_for_pid(pid) {
            self.task = task;
            self.regions = get_readable_regions(task);
            self.selected_index = 0;
            self.buffer.clear();
            self.last_buffer.clear();
            self.flash_bytes.clear();
            if !self.regions.is_empty() {
                if let Some(buf) = read_memory(task, self.regions[0].start, self.read_size) {
                    self.buffer = buf.clone();
                    self.last_buffer = buf;
                }
            }
        }
    }
    fn update_flash_bytes(&mut self, new_buffer: &[u8]) {
        self.flash_bytes.resize(new_buffer.len(), None);

        for (i, &b) in new_buffer.iter().enumerate() {
            if self.last_buffer.get(i) != Some(&b) {
                self.flash_bytes[i] = Some(Instant::now());
            }
        }
    }

    fn filter_regions(&self) -> Vec<(usize, MemoryRegion)> {
        let filter = self.filter_text.to_lowercase();
        self.regions.iter().enumerate()
            .filter(|(_i, r)| {
                let addr_str = format!("0x{:X}", r.start).to_lowercase();
                let size_str = format!("{}", r.size);
                addr_str.contains(&filter) || size_str.contains(&filter)
            })
            .map(|(i, r)| (i, r.clone()))
            .collect()
    }
}

fn prot_to_string(prot: i32) -> String {
    let r = if (prot & mach2::vm_prot::VM_PROT_READ) != 0 { "R" } else { "-" };
    let w = if (prot & mach2::vm_prot::VM_PROT_WRITE) != 0 { "W" } else { "-" };
    let x = if (prot & mach2::vm_prot::VM_PROT_EXECUTE) != 0 { "X" } else { "-" };
    format!("{}{}{}", r, w, x)
}

impl App for MemoryViewerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        // Top controls
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label("Target process:");

                let mut new_selection: Option<usize> = None;

                egui::ComboBox::from_id_salt("process_dropdown")
                    .selected_text(&self.process_list[self.selected_process_index].0)
                    .show_ui(ui, |ui| {
                        for (i, (name, _pid)) in self.process_list.iter().enumerate() {
                            if ui.selectable_label(i == self.selected_process_index, name).clicked() {
                                new_selection = Some(i);
                            }
                        }
                    });
                if let Some(idx) = new_selection {
                    self.set_target_process(idx);
                }

                ui.separator();

                ui.label("Region filter:");
                ui.text_edit_singleline(&mut self.filter_text);

                ui.separator();

                ui.label("Read size (bytes):");
                ui.add(egui::DragValue::new(&mut self.read_size).clamp_range(16..=65536));

                ui.separator();

                ui.label("Refresh interval (ms):");
                ui.add(egui::DragValue::new(&mut self.refresh_ms).clamp_range(100..=5000));

                ui.separator();

                if ui.button(if self.pause { "▶️ Resume" } else { "⏸ Pause" }).clicked() {
                    self.pause = !self.pause;
                }
            });
        });

        // Left side panel : regions
        egui::SidePanel::left("region_list").resizable(true).show(ctx, |ui| {
            ui.heading("Memory regions");
            ui.separator();

            let filtered = self.filter_regions();
            ScrollArea::vertical().show(ui, |ui| {
                for (i, region) in filtered.iter() {
                    let label = format!("0x{:X} - 0x{:X} ({}) [{}]", region.start, region.end, region.size, prot_to_string(region.protection as i32));
                    let selected = *i == self.selected_index;
                    if ui.selectable_label(selected, label).clicked() {
                        self.selected_index = *i;
                        // reset buffers on new region selection
                        self.buffer.clear();
                        self.last_buffer.clear();
                        self.flash_bytes.clear();
                    }
                }
            });
        });

        // Read memory if not paused and enough time elapsed
        if !self.pause && (self.last_update.elapsed().as_millis() as u64) >= self.refresh_ms {
            let region = &self.regions[self.selected_index];
            if let Some(new_buffer) = read_memory(self.task, region.start, self.read_size) {
                self.update_flash_bytes(&new_buffer);
                self.last_buffer = self.buffer.clone();
                self.buffer = new_buffer;
                self.last_update = Instant::now();
            }
        }

        // Central panel: hex display with byte-level flash
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Memory contents (hex):");

            ScrollArea::vertical().show(ui, |ui| {
                for (line_idx, chunk) in self.buffer.chunks(16).enumerate() {
                    let addr = self.regions[self.selected_index].start + (line_idx * 16) as u64;
                    let available_width = ui.available_width();
                    let row_height = 20.0;
                    let (_, rect) = ui.allocate_space(egui::Vec2::new(available_width, row_height));
                    let painter = ui.painter();

                    // Prepare hex and ascii strings with space for paint behind each byte
                    let mut hex_parts = Vec::with_capacity(chunk.len());
                    let mut ascii_parts = Vec::with_capacity(chunk.len());

                    for (i, &byte) in chunk.iter().enumerate() {
                        let idx = line_idx * 16 + i;
                        let flash = self.flash_bytes.get(idx)
                            .and_then(|opt| opt.as_ref())
                            .map_or(false, |t| t.elapsed().as_millis() < FLASH_MS as u128);

                        if flash {
                            // Calculate rect for the hex byte
                            // Each hex byte + space ~3 chars, monospace ~8 pixels per char
                            let hex_x = rect.min.x + 10.0 + i as f32 * 24.0;
                            let hex_rect = egui::Rect::from_min_size(
                                egui::pos2(hex_x, rect.min.y),
                                egui::vec2(20.0, row_height),
                            );
                            painter.rect_filled(hex_rect, 2.0, egui::Color32::from_rgba_unmultiplied(255, 100, 100, 150));

                            // Similarly for ascii char (starts at ~10 + 16*24 = 394 px offset)
                            let ascii_x = rect.min.x + 10.0 + 16.0 * 24.0 + i as f32 * 14.0;
                            let ascii_rect = egui::Rect::from_min_size(
                                egui::pos2(ascii_x, rect.min.y),
                                egui::vec2(12.0, row_height),
                            );
                            painter.rect_filled(ascii_rect, 2.0, egui::Color32::from_rgba_unmultiplied(255, 100, 100, 150));
                        }

                        hex_parts.push(format!("{:02X} ", byte));
                        ascii_parts.push(if byte.is_ascii_graphic() || byte == b' ' {
                            byte as char
                        } else {
                            '.'
                        });
                    }

                    let hex_str = hex_parts.concat();
                    let ascii_str: String = ascii_parts.iter().collect();

                    ui.allocate_ui_at_rect(rect, |ui| {
                        ui.monospace(format!("{:08X} | {} {}", addr, hex_str, ascii_str));
                    });
                }
            });
        });
    }
}

fn main() -> Result<(), eframe::Error> {
    let mut process_list = list_user_processes();
    process_list.sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase()));

    if process_list.is_empty() {
        panic!("❌ No user processes found!");
    }

    let selected_process_index = 1;
    let (name, pid) = process_list[selected_process_index].clone();
    let task = get_task_for_pid(pid).expect("❌ task_for_pid failed");

    let regions = get_readable_regions(task);
    if regions.is_empty() {
        panic!("❌ No readable memory regions found!");
    }

    let buffer = read_memory(task, regions[0].start, 512).unwrap_or_default();

    let app = MemoryViewerApp {
        task,
        regions,
        selected_index: 0,
        last_buffer: buffer.clone(),
        buffer,
        last_update: Instant::now(),
        refresh_ms: 500,
        pause: false,
        filter_text: String::new(),
        read_size: 512,
        flash_bytes: vec![],
        process_list,
        selected_process_index,
    };

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 800.0])
            .with_title(format!("🧠 Memory Viewer for - {} - {}", name, pid)),
        ..Default::default()
    };

    eframe::run_native("🧠 Memory Viewer", options, Box::new(|_cc| Ok(Box::new(app))))
}
