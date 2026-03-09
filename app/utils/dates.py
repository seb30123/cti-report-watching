from datetime import datetime
from dateutil import parser

def parse_dt(value) -> datetime | None : 
    if not value : 
        return None
    try : 
        return parser.parse(str(value))
    except Exception : 
        return None
    
    