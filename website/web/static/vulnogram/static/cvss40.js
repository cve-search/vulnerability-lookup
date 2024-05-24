
// Comes from https://www.first.org/cvss/cvss-v4.0.json, slightly modified
// to match the metric groups without false-positives and to avoid double-capture
// of Provider Urgency (U) due to multi-char values.
const errors = {
    InvalidMetric: class extends Error {
        constructor(version, metric) {
            super('invalid CVSS v' + version + ' metric ' + metric);
            this.version = version;
            this.metric = metric;
        }
    },
    InvalidMetricValue: class extends Error {
        constructor(version, metric, value) {
            super('invalid CVSS v' + version + ' value ' + value + ' for metric ' + metric);
            this.version = version;
            this.metric = metric;
            this.value = value;
        }
    }
}

const re = /^CVSS:4[.]0(\/AV:[NALP])(\/AC:[LH])(\/AT:[NP])(\/PR:[NLH])(\/UI:[NPA])(\/VC:[HLN])(\/VI:[HLN])(\/VA:[HLN])(\/SC:[HLN])(\/SI:[HLN])(\/SA:[HLN])(\/E:[XAPU])?(\/CR:[XHML])?(\/IR:[XHML])?(\/AR:[XHML])?(\/MAV:[XNALP])?(\/MAC:[XLH])?(\/MAT:[XNP])?(\/MPR:[XNLH])?(\/MUI:[XNPA])?(\/MVC:[XNLH])?(\/MVI:[XNLH])?(\/MVA:[XNLH])?(\/MSC:[XNLH])?(\/MSI:[XNLHS])?(\/MSA:[XNLHS])?(\/S:[XNP])?(\/AU:[XNY])?(\/R:[XAUI])?(\/V:[XDC])?(\/RE:[XLMH])?(\/U:(?:X|Clear|Green|Amber|Red))?$/g;
/**
 * Implementation of the CVSS v4.0 specification (https://www.first.org/cvss/v4.0/specification-document).
 */
export class CVSS40 {
    /**
     * Construct a CVSS v4.0 object, and parse the vector if provided.
     * If not, the Base metrics is set to the default values (score = 0).
     *
     * @param vector The vector to parse.
     * @throws When the vector is invalid.
     */
    constructor(vector = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N') {
        this._metrics = {
            // Set default values of non-mandatory metrics : Not Defined (X)
            // => Threat
            'E': 'X',
            // => Environmental
            'CR': 'X', 'IR': 'X', 'AR': 'X', 'MAV': 'X', 'MAC': 'X', 'MAT': 'X', 'MPR': 'X', 'MUI': 'X', 'MVC': 'X', 'MVI': 'X', 'MVA': 'X', 'MSC': 'X', 'MSI': 'X', 'MSA': 'X',
            // => Supplemental
            'S': 'X', 'AU': 'X', 'R': 'X', 'V': 'X', 'RE': 'X', 'U': 'X',
        };
        this.parse(vector);
    }
    /**
     * Parse the provided vector.
     * Makes use of the regex for code simplicity, but we could use the
     * `metrics` constant to provide better accurate error messages.
     *
     * @param vector The vector to parse.
     * @throws When the vector is invalid.
     */
    parse(vector) {
        // Ensure input is valid according to the regular expression
        let matches = vector.matchAll(re).next().value;
        if (matches == undefined) {
            throw new Error('invalid CVSS v4.0 vector');
        }
        // Skip prefix
        matches.shift();
        // Parse each metric group
        for (let match of matches) {
            if (match == undefined) {
                continue;
            }
            match = match.slice(1);
            const pts = match.split(':');
            this._metrics[pts[0]] = pts[1];
        }
    }
    /**
     * Return the vector string representation of the CVSS v4.0 object.
     *
     * @return The vector string representation.
     */
    Vector() {
        let vector = 'CVSS:4.0';
        for (const [om] of Object.entries(table23)) {
            const metric = this.Get(om);
            // Add the value iif was set and is not 'X' (Not Defined)
            if (metric == undefined || metric == 'X') {
                continue;
            }
            vector = vector.concat('/', om, ':', metric);
        }
        return vector;
    }
    /**
     * Get the metric value given its value (e.g. 'AV').
     *
     * @param metric The metric to get the value of.
     * @return The corresponding metric value.
     * @throws Metric does not exist.
     */
    Get(metric) {
        const v = this._metrics[metric];
        if (v == undefined) {
            throw new errors.InvalidMetric('4.0', metric);
        }
        return v;
    }
    /**
     * Set the metric value given its key and value (e.g. 'AV' and 'L').
     *
     * @param metric The metric to set the value of.
     * @param value The corresponding metric value.
     * @throws Metric does not exist or has an invalid value.
     */
    Set(metric, value) {
        const values = table23[metric];
        if (values == undefined) {
            throw new errors.InvalidMetric('4.0', metric);
        }
        if (!values.includes(value)) {
            throw new errors.InvalidMetricValue('4.0', metric, value);
        }
        this._metrics[metric] = value;
    }
    /**
     * Compute the CVSS v4.0 Score of the current object, given its metrics and their
     * corresponding values.
     *
     * The implementation internals are largely based upon https://github.com/pandatix/go-cvss
     * submodule 40.
     *
     * @return The score (between 0.0 and 10.0 both included).
     */
    Score() {
        // If the vulnerability does not affect the system AND the subsequent
        // system, there is no reason to try scoring what has no risk and impact.
        if (['VC', 'VI', 'VA', 'SC', 'SI', 'SA'].every((met) => this.getReal(met) == "N")) {
            return 0.0;
        }
        const mv = this.macrovector();
        const eq1 = Number(mv[0]);
        const eq2 = Number(mv[1]);
        const eq3 = Number(mv[2]);
        const eq4 = Number(mv[3]);
        const eq5 = Number(mv[4]);
        const eq6 = Number(mv[5]);
        const eqsv = mvs[mv];
        // Compute EQs next lower MacroVector
        // -> As the lower the EQ value is the bigger, the next lower MacroVector
        //    would be +1 to this one
        // -> If not possible (level+1 > level), it is set to NaN
        let lower = 0;
        let eq1nlm = NaN;
        if (eq1 < 2) { // 2 = maximum level for EQ1
            eq1nlm = mvs[String(eq1 + 1) + String(eq2) + String(eq3) + String(eq4) + String(eq5) + String(eq6)];
            lower++;
        }
        let eq2nlm = NaN;
        if (eq2 < 1) { // 1 = maximum level for EQ2
            eq2nlm = mvs[String(eq1) + String(eq2 + 1) + String(eq3) + String(eq4) + String(eq5) + String(eq6)];
            lower++;
        }
        let eq4nlm = NaN;
        if (eq4 < 2) { // 2 = maximum level for EQ4
            eq4nlm = mvs[String(eq1) + String(eq2) + String(eq3) + String(eq4 + 1) + String(eq5) + String(eq6)];
            lower++;
        }
        let eq5nlm = NaN;
        if (eq5 < 2) { // 2 = maximum level for EQ5
            eq5nlm = mvs[String(eq1) + String(eq2) + String(eq3) + String(eq4) + String(eq5 + 1) + String(eq6)];
            lower++;
        }
        // /!\ As EQ3 and EQ6 are related, we can't do the same as it could produce
        // eq3=2 and eq6=0 which is impossible thus will have a lookup (for EQ3) of 0.
        // This would fail the further computations.
        let eq3eq6nlm = NaN;
        if (eq3 == 1 && eq6 == 1) {
            // 11 -> 21
            eq3eq6nlm = mvs[String(eq1) + String(eq2) + String(eq3 + 1) + String(eq4) + String(eq5) + String(eq6)];
            lower++;
        }
        else if (eq3 == 0 && eq6 == 1) {
            // 01 -> 11
            eq3eq6nlm = mvs[String(eq1) + String(eq2) + String(eq3 + 1) + String(eq4) + String(eq5) + String(eq6)];
            lower++;
        }
        else if (eq3 == 1 && eq6 == 0) {
            // 10 -> 11
            eq3eq6nlm = mvs[String(eq1) + String(eq2) + String(eq3) + String(eq4) + String(eq5) + String(eq6 + 1)];
            lower++;
        }
        else if (eq3 == 0 && eq6 == 0) {
            // 00 -> 01 OR 00 -> 10, takes the bigger
            eq3eq6nlm = Math.max(mvs[String(eq1) + String(eq2) + String(eq3 + 1) + String(eq4) + String(eq5) + String(eq6)], mvs[String(eq1) + String(eq2) + String(eq3) + String(eq4) + String(eq5) + String(eq6 + 1)]);
            lower++;
        }
        // 1.a - Compute maximal scoring (absolute) differences
        const msd = ((nlm) => {
            let msd = Math.abs(nlm - eqsv);
            if (isNaN(msd)) {
                return 0;
            }
            return msd;
        });
        let eq1msd = msd(eq1nlm);
        let eq2msd = msd(eq2nlm);
        let eq3eq6msd = msd(eq3eq6nlm);
        let eq4msd = msd(eq4nlm);
        let eq5msd = msd(eq5nlm);
        // 1.b - Compute the severity distances of the to-be scored vectors
        //       to a highest AND higher severity vector in the MacroVector
        let eq1svdst = 0, eq2svdst = 0, eq3eq6svdst = 0, eq4svdst = 0, eq5svdst = 0;
        for (const eq1mx of highestSeverityVectors[1][eq1]) {
            for (const eq2mx of highestSeverityVectors[2][eq2]) {
                for (const eq3eq6mx of highestSeverityVectors[3][eq3][eq6]) {
                    for (const eq4mx of highestSeverityVectors[4][eq4]) {
                        // Don't need to iterate over eq5, only one dimension is involved
                        // so the highest of a MV's EQ is always unique, such that iterating
                        // over it would lead to nothing but cognitive complexity.
                        const partial = [eq1mx, eq2mx, eq3eq6mx, eq4mx].join('/');
                        // Compute severity distances
                        const avsvdst = CVSS40.severityDistance('AV', this.getReal('AV'), CVSS40.getValue(partial, 'AV'));
                        const prsvdst = CVSS40.severityDistance('PR', this.getReal('PR'), CVSS40.getValue(partial, 'PR'));
                        const uisvdst = CVSS40.severityDistance('UI', this.getReal('UI'), CVSS40.getValue(partial, 'UI'));
                        const acsvdst = CVSS40.severityDistance('AC', this.getReal('AC'), CVSS40.getValue(partial, 'AC'));
                        const atsvdst = CVSS40.severityDistance('AT', this.getReal('AT'), CVSS40.getValue(partial, 'AT'));
                        const vcsvdst = CVSS40.severityDistance('VC', this.getReal('VC'), CVSS40.getValue(partial, 'VC'));
                        const visvdst = CVSS40.severityDistance('VI', this.getReal('VI'), CVSS40.getValue(partial, 'VI'));
                        const vasvdst = CVSS40.severityDistance('VA', this.getReal('VA'), CVSS40.getValue(partial, 'VA'));
                        const scsvdst = CVSS40.severityDistance('SC', this.getReal('SC'), CVSS40.getValue(partial, 'SC'));
                        const sisvdst = CVSS40.severityDistance('SI', this.getReal('SI'), CVSS40.getValue(partial, 'SI'));
                        const sasvdst = CVSS40.severityDistance('SA', this.getReal('SA'), CVSS40.getValue(partial, 'SA'));
                        const crsvdst = CVSS40.severityDistance('CR', this.getReal('CR'), CVSS40.getValue(partial, 'CR'));
                        const irsvdst = CVSS40.severityDistance('IR', this.getReal('IR'), CVSS40.getValue(partial, 'IR'));
                        const arsvdst = CVSS40.severityDistance('AR', this.getReal('AR'), CVSS40.getValue(partial, 'AR'));
                        if ([avsvdst, prsvdst, uisvdst, acsvdst, atsvdst, vcsvdst, visvdst, vasvdst, scsvdst, sisvdst, sasvdst, crsvdst, irsvdst, arsvdst].some((met) => met < 0)) {
                            continue;
                        }
                        eq1svdst = avsvdst + prsvdst + uisvdst;
                        eq2svdst = acsvdst + atsvdst;
                        eq3eq6svdst = vcsvdst + visvdst + vasvdst + crsvdst + irsvdst + arsvdst;
                        eq4svdst = scsvdst + sisvdst + sasvdst;
                        // Don't need to compute E severity distance as the maximum will
                        // always remain the same due to only 1 dimension involved in EQ5.
                        eq5svdst = 0;
                        break;
                    }
                }
            }
        }
        // 1.c - Compute proportion of the distance
        const eq1prop = eq1svdst / (depth[1][eq1] + 1);
        const eq2prop = eq2svdst / (depth[2][eq2] + 1);
        const eq3eq6prop = eq3eq6svdst / (depth[3][eq3][eq6] + 1);
        const eq4prop = eq4svdst / (depth[4][eq4] + 1);
        const eq5prop = eq5svdst / (depth[5][eq5] + 1);
        // 1.d - Multiply maximal scoring diff. by prop. of distance
        eq1msd *= eq1prop;
        eq2msd *= eq2prop;
        eq3eq6msd *= eq3eq6prop;
        eq4msd *= eq4prop;
        eq5msd *= eq5prop;
        // 2 - Compute mean
        let mean = 0;
        if (lower != 0) {
            mean = (eq1msd + eq2msd + eq3eq6msd + eq4msd + eq5msd) / lower;
        }
        // 3 - Compute score
        return CVSS40.roundup(eqsv - mean);
    }
    /**
     * Gives the nomenclature of the current CVSS v4.0 object i.e. its structure
     * according to the Base, Threat and Environmental metric groups.
     *
     * @return The nomenclature string.
     */
    Nomenclature() {
        const isDefined = ((metric) => this.Get(metric) != 'X');
        const t = (['E']).some(isDefined);
        const e = (['CR', 'IR', 'AR', 'MAV', 'MAC', 'MAT', 'MPR', 'MUI', 'MVC', 'MVI', 'MVA', 'MSC', 'MSI', 'MSA']).some(isDefined);
        if (t) {
            if (e) {
                return 'CVSS-BTE';
            }
            return 'CVSS-BT';
        }
        if (e) {
            return 'CVSS-BE';
        }
        return 'CVSS-B';
    }
    getReal(metric) {
        if (['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA'].includes(metric)) {
            const v = this.Get('M' + metric);
            if (v != 'X') {
                return v;
            }
            return this.Get(metric);
        }
        const v = this.Get(metric);
        if (v != 'X') {
            return v;
        }
        // If it was not a base metric then defaults
        switch (metric) {
            case 'CR':
            case 'IR':
            case 'AR':
                return 'H';
            case 'E':
                return 'A';
        }
    }
    macrovector() {
        const av = this.getReal('AV');
        const ac = this.getReal('AC');
        const at = this.getReal('AT');
        const pr = this.getReal('PR');
        const ui = this.getReal('UI');
        const vc = this.getReal('VC');
        const vi = this.getReal('VI');
        const va = this.getReal('VA');
        const sc = this.getReal('SC');
        const si = this.getReal('SI');
        const sa = this.getReal('SA');
        const e = this.getReal('E');
        const cr = this.getReal('CR');
        const ir = this.getReal('IR');
        const ar = this.getReal('AR');
        // Compte MacroVectors
        // => EQ1
        let eq1 = '0';
        if (av == 'N' && pr == 'N' && ui == 'N') {
            eq1 = '0';
        }
        else if ((av == 'N' || pr == 'N' || ui == 'N') && !(av == 'N' && pr == 'N' && ui == 'N') && !(av == 'P')) {
            eq1 = '1';
        }
        else if (av == 'P' || !(av == 'N' || pr == 'N' || ui == 'N')) {
            eq1 = '2';
        }
        // EQ2
        let eq2 = '0';
        if (!(ac == 'L' && at == 'N')) {
            eq2 = '1';
        }
        // EQ3
        let eq3 = '0';
        if (vc == 'H' && vi == 'H') {
            eq3 = '0';
        }
        else if (!(vc == 'H' && vi == 'H') && (vc == 'H' || vi == 'H' || va == 'H')) {
            eq3 = '1';
        }
        else if (!(vc == 'H' || vi == 'H' || va == 'H')) {
            eq3 = '2';
        }
        // EQ4
        let eq4 = '0';
        if (si == 'S' || sa == 'S') {
            eq4 = '0';
        }
        else if (!(si == 'S' || sa == 'S') && (sc == 'H' || si == 'H' || sa == 'H')) {
            eq4 = '1';
        }
        else if (!(si == 'S' || sa == 'S') && !(sc == 'H' || si == 'H' || sa == 'H')) {
            eq4 = '2';
        }
        // EQ5
        let eq5 = '0';
        if (e == 'A' || e == 'X') {
            eq5 = '0';
        }
        else if (e == 'P') {
            eq5 = '1';
        }
        else if (e == 'U') {
            eq5 = '2';
        }
        // EQ6
        let eq6 = '0';
        const crh = (cr == 'H' || cr == 'X');
        const irh = (ir == 'H' || ir == 'X');
        const arh = (ar == 'H' || ar == 'X');
        if ((crh && vc == 'H') || (irh && vi == 'H') || (arh && va == 'H')) {
            eq6 = '0';
        }
        else if (!(crh && vc == 'H') && !(irh && vi == 'H') && !(arh && va == 'H')) {
            eq6 = '1';
        }
        return eq1 + eq2 + eq3 + eq4 + eq5 + eq6;
    }
    static severityDistance(metric, vecVal, mxVal) {
        const values = sevIdx[metric];
        return values.indexOf(vecVal) - values.indexOf(mxVal);
    }
    static getValue(partial, metric) {
        const pts = partial.split('/');
        for (const pt of pts) {
            let pts = pt.split(':');
            if (pts[0] == metric) {
                return pts[1];
            }
        }
    }
    static roundup(score) {
        return +(score.toFixed(1));
    }
    /**
     * Give the corresponding rating of the provided score.
     *
     * @param score The score to rate.
     * @return The rating.
     * @throws When the score is out of bounds.
     */
    static Rating(score) {
        if (score < 0 || score > 10) {
            throw new Error('score out of bounds');
        }
        if (score >= 9.0) {
            return 'CRITICAL';
        }
        if (score >= 7.0) {
            return 'HIGH';
        }
        if (score >= 4.0) {
            return 'MEDIUM';
        }
        if (score >= 0.1) {
            return 'LOW';
        }
        return 'NONE';
    }
}
;
// Metrics defined in Table 23.
const table23 = {
    // Base (11 metrics)
    'AV': ['N', 'A', 'L', 'P'],
    'AC': ['L', 'H'],
    'AT': ['N', 'P'],
    'PR': ['N', 'L', 'H'],
    'UI': ['N', 'P', 'A'],
    'VC': ['H', 'L', 'N'],
    'VI': ['H', 'L', 'N'],
    'VA': ['H', 'L', 'N'],
    'SC': ['H', 'L', 'N'],
    'SI': ['H', 'L', 'N'],
    'SA': ['H', 'L', 'N'],
    // Threat (1 metric)
    'E': ['X', 'A', 'P', 'U'],
    // Environmental (14 metrics)
    'CR': ['X', 'H', 'M', 'L'],
    'IR': ['X', 'H', 'M', 'L'],
    'AR': ['X', 'H', 'M', 'L'],
    'MAV': ['X', 'N', 'A', 'L', 'P'],
    'MAC': ['X', 'L', 'H'],
    'MAT': ['X', 'N', 'P'],
    'MPR': ['X', 'N', 'L', 'H'],
    'MUI': ['X', 'N', 'P', 'A'],
    'MVC': ['X', 'H', 'L', 'N'],
    'MVI': ['X', 'H', 'L', 'N'],
    'MVA': ['X', 'H', 'L', 'N'],
    'MSC': ['X', 'H', 'L', 'N'],
    'MSI': ['X', 'S', 'H', 'L', 'N'],
    'MSA': ['X', 'S', 'H', 'L', 'N'],
    // Supplemental (6 metrics)
    'S': ['X', 'N', 'P'],
    'AU': ['X', 'N', 'Y'],
    'R': ['X', 'A', 'U', 'I'],
    'V': ['X', 'D', 'C'],
    'RE': ['X', 'L', 'M', 'H'],
    'U': ['X', 'Clear', 'Green', 'Amber', 'Red'],
};
const highestSeverityVectors = {
    // EQ1 - Table 24
    1: {
        0: ['AV:N/PR:N/UI:N'],
        1: ['AV:A/PR:N/UI:N', 'AV:N/PR:L/UI:N', 'AV:N/PR:N/UI:P'],
        2: ['AV:P/PR:N/UI:N', 'AV:A/PR:L/UI:P'],
    },
    // EQ2 - Table 25
    2: {
        0: ['AC:L/AT:N'],
        1: ['AC:H/AT:N', 'AC:L/AT:P'],
    },
    // EQ3-EQ6 - Table 30
    3: {
        0: {
            0: ['VC:H/VI:H/VA:H/CR:H/IR:H/AR:H'],
            1: ['VC:H/VI:H/VA:L/CR:M/IR:M/AR:H', 'VC:H/VI:H/VA:H/CR:M/IR:M/AR:M'],
        },
        1: {
            0: ['VC:L/VI:H/VA:H/CR:H/IR:H/AR:H', 'VC:H/VI:L/VA:H/CR:H/IR:H/AR:H'],
            1: ['VC:L/VI:H/VA:L/CR:H/IR:M/AR:H', 'VC:L/VI:H/VA:H/CR:H/IR:M/AR:M', 'VC:H/VI:L/VA:H/CR:M/IR:H/AR:M', 'VC:H/VI:L/VA:L/CR:M/IR:H/AR:H', 'VC:L/VI:L/VA:H/CR:H/IR:H/AR:M'],
        },
        2: {
            1: ['VC:L/VI:L/VA:L/CR:H/IR:H/AR:H']
        },
    },
    // EQ4 - Table 27
    4: {
        0: ['SC:H/SI:S/SA:S'],
        1: ['SC:H/SI:H/SA:H'],
        2: ['SC:L/SI:L/SA:L'],
    },
    // EQ5 - Table 28 (useless in fact, is not involved in score computation due to only 1 dimension)
    5: {
        0: ['E:A'],
        1: ['E:P'],
        2: ['E:U'],
    },
};
const sevIdx = {
    // Base metrics
    'AV': ['N', 'A', 'L', 'P'],
    'AC': ['L', 'H'],
    'AT': ['N', 'P'],
    'PR': ['N', 'L', 'H'],
    'UI': ['N', 'P', 'A'],
    'VC': ['H', 'L', 'N'],
    'VI': ['H', 'L', 'N'],
    'VA': ['H', 'L', 'N'],
    'SC': ['H', 'L', 'N'],
    'SI': ['S', 'H', 'L', 'N'],
    'SA': ['S', 'H', 'L', 'N'],
    // Threat metrics
    'E': ['A', 'P', 'U'],
    // Environmental metrics
    'CR': ['H', 'M', 'L'],
    'IR': ['H', 'M', 'L'],
    'AR': ['H', 'M', 'L'],
};
// Depths are re-computed and has been checked in github.com/pandatix/go-cvss
const depth = {
    // EQ1
    1: {
        0: 0,
        1: 3,
        2: 4,
    },
    // EQ2
    2: {
        0: 0,
        1: 1,
    },
    // EQ3-EQ6
    3: {
        0: {
            0: 6,
            1: 5,
        },
        1: {
            0: 7,
            1: 7,
        },
        2: {
            1: 9,
        },
    },
    // EQ4
    4: {
        0: 5,
        1: 4,
        2: 3,
    },
    // EQ5
    5: {
        0: 1,
        1: 1,
        2: 1,
    },
};
// MacroVectors maximum score given each EQuivalency sets.
const mvs = {
    '000000': 10,
    '000001': 9.9,
    '000010': 9.8,
    '000011': 9.5,
    '000020': 9.5,
    '000021': 9.2,
    '000100': 10,
    '000101': 9.6,
    '000110': 9.3,
    '000111': 8.7,
    '000120': 9.1,
    '000121': 8.1,
    '000200': 9.3,
    '000201': 9,
    '000210': 8.9,
    '000211': 8,
    '000220': 8.1,
    '000221': 6.8,
    '001000': 9.8,
    '001001': 9.5,
    '001010': 9.5,
    '001011': 9.2,
    '001020': 9,
    '001021': 8.4,
    '001100': 9.3,
    '001101': 9.2,
    '001110': 8.9,
    '001111': 8.1,
    '001120': 8.1,
    '001121': 6.5,
    '001200': 8.8,
    '001201': 8,
    '001210': 7.8,
    '001211': 7,
    '001220': 6.9,
    '001221': 4.8,
    '002001': 9.2,
    '002011': 8.2,
    '002021': 7.2,
    '002101': 7.9,
    '002111': 6.9,
    '002121': 5,
    '002201': 6.9,
    '002211': 5.5,
    '002221': 2.7,
    '010000': 9.9,
    '010001': 9.7,
    '010010': 9.5,
    '010011': 9.2,
    '010020': 9.2,
    '010021': 8.5,
    '010100': 9.5,
    '010101': 9.1,
    '010110': 9,
    '010111': 8.3,
    '010120': 8.4,
    '010121': 7.1,
    '010200': 9.2,
    '010201': 8.1,
    '010210': 8.2,
    '010211': 7.1,
    '010220': 7.2,
    '010221': 5.3,
    '011000': 9.5,
    '011001': 9.3,
    '011010': 9.2,
    '011011': 8.5,
    '011020': 8.5,
    '011021': 7.3,
    '011100': 9.2,
    '011101': 8.2,
    '011110': 8,
    '011111': 7.2,
    '011120': 7,
    '011121': 5.9,
    '011200': 8.4,
    '011201': 7,
    '011210': 7.1,
    '011211': 5.2,
    '011220': 5,
    '011221': 3,
    '012001': 8.6,
    '012011': 7.5,
    '012021': 5.2,
    '012101': 7.1,
    '012111': 5.2,
    '012121': 2.9,
    '012201': 6.3,
    '012211': 2.9,
    '012221': 1.7,
    '100000': 9.8,
    '100001': 9.5,
    '100010': 9.4,
    '100011': 8.7,
    '100020': 9.1,
    '100021': 8.1,
    '100100': 9.4,
    '100101': 8.9,
    '100110': 8.6,
    '100111': 7.4,
    '100120': 7.7,
    '100121': 6.4,
    '100200': 8.7,
    '100201': 7.5,
    '100210': 7.4,
    '100211': 6.3,
    '100220': 6.3,
    '100221': 4.9,
    '101000': 9.4,
    '101001': 8.9,
    '101010': 8.8,
    '101011': 7.7,
    '101020': 7.6,
    '101021': 6.7,
    '101100': 8.6,
    '101101': 7.6,
    '101110': 7.4,
    '101111': 5.8,
    '101120': 5.9,
    '101121': 5,
    '101200': 7.2,
    '101201': 5.7,
    '101210': 5.7,
    '101211': 5.2,
    '101220': 5.2,
    '101221': 2.5,
    '102001': 8.3,
    '102011': 7,
    '102021': 5.4,
    '102101': 6.5,
    '102111': 5.8,
    '102121': 2.6,
    '102201': 5.3,
    '102211': 2.1,
    '102221': 1.3,
    '110000': 9.5,
    '110001': 9,
    '110010': 8.8,
    '110011': 7.6,
    '110020': 7.6,
    '110021': 7,
    '110100': 9,
    '110101': 7.7,
    '110110': 7.5,
    '110111': 6.2,
    '110120': 6.1,
    '110121': 5.3,
    '110200': 7.7,
    '110201': 6.6,
    '110210': 6.8,
    '110211': 5.9,
    '110220': 5.2,
    '110221': 3,
    '111000': 8.9,
    '111001': 7.8,
    '111010': 7.6,
    '111011': 6.7,
    '111020': 6.2,
    '111021': 5.8,
    '111100': 7.4,
    '111101': 5.9,
    '111110': 5.7,
    '111111': 5.7,
    '111120': 4.7,
    '111121': 2.3,
    '111200': 6.1,
    '111201': 5.2,
    '111210': 5.7,
    '111211': 2.9,
    '111220': 2.4,
    '111221': 1.6,
    '112001': 7.1,
    '112011': 5.9,
    '112021': 3,
    '112101': 5.8,
    '112111': 2.6,
    '112121': 1.5,
    '112201': 2.3,
    '112211': 1.3,
    '112221': 0.6,
    '200000': 9.3,
    '200001': 8.7,
    '200010': 8.6,
    '200011': 7.2,
    '200020': 7.5,
    '200021': 5.8,
    '200100': 8.6,
    '200101': 7.4,
    '200110': 7.4,
    '200111': 6.1,
    '200120': 5.6,
    '200121': 3.4,
    '200200': 7,
    '200201': 5.4,
    '200210': 5.2,
    '200211': 4,
    '200220': 4,
    '200221': 2.2,
    '201000': 8.5,
    '201001': 7.5,
    '201010': 7.4,
    '201011': 5.5,
    '201020': 6.2,
    '201021': 5.1,
    '201100': 7.2,
    '201101': 5.7,
    '201110': 5.5,
    '201111': 4.1,
    '201120': 4.6,
    '201121': 1.9,
    '201200': 5.3,
    '201201': 3.6,
    '201210': 3.4,
    '201211': 1.9,
    '201220': 1.9,
    '201221': 0.8,
    '202001': 6.4,
    '202011': 5.1,
    '202021': 2,
    '202101': 4.7,
    '202111': 2.1,
    '202121': 1.1,
    '202201': 2.4,
    '202211': 0.9,
    '202221': 0.4,
    '210000': 8.8,
    '210001': 7.5,
    '210010': 7.3,
    '210011': 5.3,
    '210020': 6,
    '210021': 5,
    '210100': 7.3,
    '210101': 5.5,
    '210110': 5.9,
    '210111': 4,
    '210120': 4.1,
    '210121': 2,
    '210200': 5.4,
    '210201': 4.3,
    '210210': 4.5,
    '210211': 2.2,
    '210220': 2,
    '210221': 1.1,
    '211000': 7.5,
    '211001': 5.5,
    '211010': 5.8,
    '211011': 4.5,
    '211020': 4,
    '211021': 2.1,
    '211100': 6.1,
    '211101': 5.1,
    '211110': 4.8,
    '211111': 1.8,
    '211120': 2,
    '211121': 0.9,
    '211200': 4.6,
    '211201': 1.8,
    '211210': 1.7,
    '211211': 0.7,
    '211220': 0.8,
    '211221': 0.2,
    '212001': 5.3,
    '212011': 2.4,
    '212021': 1.4,
    '212101': 2.4,
    '212111': 1.2,
    '212121': 0.5,
    '212201': 1,
    '212211': 0.3,
    '212221': 0.1,
};
