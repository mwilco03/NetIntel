export namespace models {
	
	export class HostRiskEntry {
	    ip: string;
	    hostname?: string;
	    risk: number;
	
	    static createFrom(source: any = {}) {
	        return new HostRiskEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ip = source["ip"];
	        this.hostname = source["hostname"];
	        this.risk = source["risk"];
	    }
	}
	export class DashboardStats {
	    totalHosts: number;
	    hostsUp: number;
	    totalPorts: number;
	    cleartextCount: number;
	    avgRisk: number;
	    topRisks: HostRiskEntry[];
	    osDist: Record<string, number>;
	    severityCounts?: Record<string, number>;
	
	    static createFrom(source: any = {}) {
	        return new DashboardStats(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.totalHosts = source["totalHosts"];
	        this.hostsUp = source["hostsUp"];
	        this.totalPorts = source["totalPorts"];
	        this.cleartextCount = source["cleartextCount"];
	        this.avgRisk = source["avgRisk"];
	        this.topRisks = this.convertValues(source["topRisks"], HostRiskEntry);
	        this.osDist = source["osDist"];
	        this.severityCounts = source["severityCounts"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class NessusFinding {
	    pluginID: number;
	    pluginName: string;
	    severity: number;
	    severityLabel: string;
	    riskFactor: string;
	    cvss?: number;
	    cvss3?: number;
	    vpr?: number;
	    cves?: string[];
	    cpe?: string;
	    synopsis?: string;
	    description?: string;
	    solution?: string;
	    output?: string;
	    exploitAvailable: boolean;
	    stigSeverity?: string;
	    references?: string;
	    xrefs?: string[];
	    port: number;
	    proto?: string;
	    hostIp?: string;
	
	    static createFrom(source: any = {}) {
	        return new NessusFinding(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.pluginID = source["pluginID"];
	        this.pluginName = source["pluginName"];
	        this.severity = source["severity"];
	        this.severityLabel = source["severityLabel"];
	        this.riskFactor = source["riskFactor"];
	        this.cvss = source["cvss"];
	        this.cvss3 = source["cvss3"];
	        this.vpr = source["vpr"];
	        this.cves = source["cves"];
	        this.cpe = source["cpe"];
	        this.synopsis = source["synopsis"];
	        this.description = source["description"];
	        this.solution = source["solution"];
	        this.output = source["output"];
	        this.exploitAvailable = source["exploitAvailable"];
	        this.stigSeverity = source["stigSeverity"];
	        this.references = source["references"];
	        this.xrefs = source["xrefs"];
	        this.port = source["port"];
	        this.proto = source["proto"];
	        this.hostIp = source["hostIp"];
	    }
	}
	export class TraceHop {
	    ttl: number;
	    ip: string;
	    host?: string;
	    rtt: number;
	
	    static createFrom(source: any = {}) {
	        return new TraceHop(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ttl = source["ttl"];
	        this.ip = source["ip"];
	        this.host = source["host"];
	        this.rtt = source["rtt"];
	    }
	}
	export class Port {
	    port: number;
	    proto: string;
	    state: string;
	    svc: string;
	    product?: string;
	    version?: string;
	    cpe?: string;
	
	    static createFrom(source: any = {}) {
	        return new Port(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.port = source["port"];
	        this.proto = source["proto"];
	        this.state = source["state"];
	        this.svc = source["svc"];
	        this.product = source["product"];
	        this.version = source["version"];
	        this.cpe = source["cpe"];
	    }
	}
	export class OSMatch {
	    name: string;
	    accuracy: number;
	
	    static createFrom(source: any = {}) {
	        return new OSMatch(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.accuracy = source["accuracy"];
	    }
	}
	export class Host {
	    ip: string;
	    mac?: string;
	    macVendor?: string;
	    hostname?: string;
	    netbiosName?: string;
	    status: string;
	    os?: OSMatch[];
	    ports?: Port[];
	    trace?: TraceHop[];
	    cpes?: string[];
	    nessusFindings?: NessusFinding[];
	    credentialedScan?: boolean;
	    riskScore: number;
	    cleartextCount: number;
	
	    static createFrom(source: any = {}) {
	        return new Host(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ip = source["ip"];
	        this.mac = source["mac"];
	        this.macVendor = source["macVendor"];
	        this.hostname = source["hostname"];
	        this.netbiosName = source["netbiosName"];
	        this.status = source["status"];
	        this.os = this.convertValues(source["os"], OSMatch);
	        this.ports = this.convertValues(source["ports"], Port);
	        this.trace = this.convertValues(source["trace"], TraceHop);
	        this.cpes = source["cpes"];
	        this.nessusFindings = this.convertValues(source["nessusFindings"], NessusFinding);
	        this.credentialedScan = source["credentialedScan"];
	        this.riskScore = source["riskScore"];
	        this.cleartextCount = source["cleartextCount"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	
	
	
	export class ScanSource {
	    name: string;
	    type: string;
	    hosts: number;
	    timestamp: string;
	
	    static createFrom(source: any = {}) {
	        return new ScanSource(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.type = source["type"];
	        this.hosts = source["hosts"];
	        this.timestamp = source["timestamp"];
	    }
	}
	export class ScanData {
	    hosts: Host[];
	    sources: ScanSource[];
	
	    static createFrom(source: any = {}) {
	        return new ScanData(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.hosts = this.convertValues(source["hosts"], Host);
	        this.sources = this.convertValues(source["sources"], ScanSource);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	

}

