// **************************************************
// Logging and error management
// **************************************************

// Logging level (if false, only log Errors)
const LOG_ALL = true

// Basic rotating log. When buffer is full, new entry overwrites oldest one
export var log = {
    MAX_LOG_ENTRIES: 100,
    logItems: [],
    next_item: 0,

    mylog_entry(_level, _desc, _item) {
    
        // Create the object to store
        var logItem = {
            timestamp: Date.now(),
            level: _level,
            desc: _desc,
            item: _item
        }
    
        // Store the object
    
        // If the list is not yet full, append a new entry to the end
        if (this.logItems.length < this.MAX_LOG_ENTRIES) {
            this.logItems.push(logItem)
            return;
        }
    
        // The list is alredy full, overwrite the oldest one and keep track of it
        this.logItems[this.next_item] = logItem
        this.next_item = this.next_item + 1
        if (this.next_item == this.MAX_LOG_ENTRIES) {
            this.next_item = 0
        }
        return;
    
    },
        
    log(_desc) {
        if (LOG_ALL) {
            var args = Array.prototype.slice.call(arguments, 1);
            console.log(_desc, args)
            this.mylog_entry("N", _desc, args)
        }
    },

    
    warn(_desc, ...additional) {
        if (LOG_ALL) {
            let msg = _desc
            // Get the stack trace if available
            try {
                let e = new Warning(_desc)
                msg = e.stack
            } catch {}
            console.warn(msg, ...additional)
            this.mylog_entry("W", msg, ...additional)
        }
    }, 

    error(_desc, ...additional) {
        let msg = _desc
        // Get the stack trace if available
        try {
            let e = new Error(_desc)
            msg = e.stack
        } catch {}
    
        console.error(msg, ...additional)
        this.mylog_entry("E", msg, ...additional)
    },  

    num_items() {
        if (this.logItems.length < this.MAX_LOG_ENTRIES) { return this.logItems.length }
        return this.MAX_LOG_ENTRIES
    },

    item(index) {
        if (index >= this.num_items()) {
            return undefined
        }

        if (this.logItems.length < this.MAX_LOG_ENTRIES) {
            return this.logItems[index]
        } else {
            let real_index = (this.next_item + index) % this.MAX_LOG_ENTRIES
            return this.logItems[real_index]
        }
    }
        
}
