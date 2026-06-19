/**
 * Pure mapping of app state to the six migration-workflow step descriptors.
 * No React/DOM — unit-testable in isolation.
 *
 * @param {object} input
 * @param {string} input.editTab - current UI edit tab
 * @param {string} input.platformView - 'panos' | 'srx'
 * @param {number} [input.analysisCount] - applied/available analysis finding count
 * @param {boolean} [input.hasTranslated] - SRX-translated policies exist
 * @param {boolean} [input.hasOutput] - SRX output has been generated
 * @param {number} [input.llmReviewedCount] - policies with _review_status === 'llm_reviewed'
 * @param {boolean} [input.mergeMode] - merge mode active
 * @param {string} input.sourceLabel - Step 1 label
 * @param {string} input.targetLabel - Step 4 label
 * @returns {Array<{id:string,num:number,label:string,sub:(string|null),optional:boolean,llm:boolean,status:('done'|'current'|'available'|'upcoming')}>}
 */
export function computeWorkflowSteps(input) {
  const {
    editTab, platformView,
    analysisCount = 0, hasTranslated = false, hasOutput = false,
    llmReviewedCount = 0, mergeMode = false,
    sourceLabel = 'Source', targetLabel = 'SRX',
  } = input;

  const sourceCurrent = platformView === 'panos' && editTab === 'rules';
  const srxCurrent = platformView === 'srx' && editTab === 'rules';
  const analysisDone = analysisCount > 0 || hasTranslated;

  return [
    {
      id: 'source', num: 1, label: sourceLabel, sub: 'edit source config',
      optional: false, llm: false,
      status: sourceCurrent ? 'current' : 'done',
    },
    {
      id: 'analysis', num: 2, label: 'Analysis', sub: 'of source config',
      optional: false, llm: false,
      status: editTab === 'analysis' ? 'current' : (analysisDone ? 'done' : 'upcoming'),
    },
    {
      id: 'review', num: 3, label: 'Review w/LLM', sub: null,
      optional: true, llm: true,
      status: editTab === 'review' ? 'current'
        : llmReviewedCount > 0 ? 'done'
        : (hasTranslated || analysisCount > 0) ? 'available'
        : 'upcoming',
    },
    {
      id: 'srx', num: 4, label: targetLabel, sub: 'edit proposed config',
      optional: false, llm: false,
      status: srxCurrent ? 'current' : (hasOutput ? 'done' : 'upcoming'),
    },
    {
      id: 'convert', num: 5, label: mergeMode ? 'Merge & Convert' : 'Convert & Export',
      sub: 'export / apply', optional: false, llm: false,
      status: editTab === 'output' ? 'current' : (hasOutput ? 'done' : 'upcoming'),
    },
    {
      id: 'day2', num: 6, label: 'Day 2 Ops', sub: null,
      optional: true, llm: false,
      status: editTab === 'day2ops' ? 'current' : 'upcoming',
    },
  ];
}
