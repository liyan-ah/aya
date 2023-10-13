#![no_std]
#![no_main]

use aya_bpf::{
    macros::{map, uprobe},
    maps::HashMap,
    programs::ProbeContext,
};

#[map]
static ARGS: HashMap<u32, u64> = HashMap::with_max_entries(24, 0);

#[uprobe]
pub fn test_stack_argument(ctx: ProbeContext) -> i32 {
    try_stack_argument(ctx).unwrap_or(0)
}

// read function arguments, and set to map.
fn try_stack_argument(ctx: ProbeContext) -> Result<i32, i64> {
    let mut stack = false;
    let mut arg = 0;
    let mut start = 0;
    loop {
        if arg > 7 {
            break;
        }
        if stack {
            let key = arg as u32;
            let value = ctx.stack_arg((arg - start) as usize).ok_or(255)?;
            if let Err(e) = ARGS.insert(&key, &value, 0) {
                return Err(e);
            }
        } else {
            let arg_v: Option<u64> = ctx.arg(arg as usize);
            if arg_v.is_none() {
                // assume that we shall read from stack now.
                stack = true;
                start = arg;
                continue;
            }
            let key = arg as u32;
            let value = arg_v.ok_or(255)?;
            if let Err(e) = ARGS.insert(&key, &value, 0) {
                return Err(e);
            }
        }
        arg += 1;
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
