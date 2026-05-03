import { anchorAssistantTopics, type AnchorAssistantTopic } from "@/lib/anchorAssistantContent";

export type AnchorAssistantReply = {
  answer: string;
  questionCategory: string;
  matchedTopic: string | null;
  answerConfidence: "high" | "medium" | "low";
  suggestedCta?: {
    label: string;
    href: string;
  };
};

const fallbackAnswer =
  "I can help with questions about ANCHOR’s governed workflows, trust surfaces, onboarding, and product boundaries. For a clinic-specific discussion, request a walkthrough.";

const offScopeClinicalPattern =
  /\b(symptom|symptoms|diagnosis|diagnose|diagnostic|treatment|treat|dose|dosage|prescribe|prescription|medication|drug|illness|disease|surgery|anesthesia|anaesthesia|antibiotic|pain relief|triage)\b/i;

function normalizeQuestion(question: string) {
  return question.toLowerCase().replace(/[^a-z0-9\s]/g, " ").replace(/\s+/g, " ").trim();
}

function scoreTopic(normalizedQuestion: string, topic: AnchorAssistantTopic) {
  return topic.keywords.reduce((score, keyword) => {
    return normalizedQuestion.includes(keyword) ? score + keyword.length : score;
  }, 0);
}

export function answerAnchorQuestion(question: string): AnchorAssistantReply {
  const normalizedQuestion = normalizeQuestion(question);

  if (!normalizedQuestion) {
    return {
      answer: fallbackAnswer,
      questionCategory: "fallback",
      matchedTopic: null,
      answerConfidence: "low",
      suggestedCta: {
        label: "Request a walkthrough",
        href: "/demo",
      },
    };
  }

  if (offScopeClinicalPattern.test(normalizedQuestion)) {
    return {
      answer:
        "I can help with questions about ANCHOR’s product, governed workflows, onboarding, and trust surfaces, but I can’t answer veterinary clinical questions or treatment questions. For a clinic-specific discussion, request a walkthrough.",
      questionCategory: "clinical_out_of_scope",
      matchedTopic: null,
      answerConfidence: "high",
      suggestedCta: {
        label: "Request a walkthrough",
        href: "/demo",
      },
    };
  }

  const bestMatch = anchorAssistantTopics
    .map((topic) => ({
      topic,
      score: scoreTopic(normalizedQuestion, topic),
    }))
    .sort((left, right) => right.score - left.score)[0];

  if (!bestMatch || bestMatch.score === 0) {
    return {
      answer: fallbackAnswer,
      questionCategory: "fallback",
      matchedTopic: null,
      answerConfidence: "low",
      suggestedCta: {
        label: "Request a walkthrough",
        href: "/demo",
      },
    };
  }

  return {
    answer: bestMatch.topic.answer,
    questionCategory: bestMatch.topic.category,
    matchedTopic: bestMatch.topic.title,
    answerConfidence: bestMatch.topic.confidence,
    suggestedCta: bestMatch.topic.suggestedCta,
  };
}
