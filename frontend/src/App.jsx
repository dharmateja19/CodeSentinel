import { useMemo, useState } from "react";

const API_URL = "http://127.0.0.1:8000";

const severityClass = (severity = "LOW") =>
	`severity-${severity.toLowerCase()}`;

const verdictClass = (verdict = "UNCERTAIN") =>
	`verdict-${verdict.toLowerCase()}`;

function StatCard({ label, value, detail, accent }) {
	return (
		<div className="panel p-5">
			<p className="text-sm muted">{label}</p>
			<p className="mt-2 text-3xl font-semibold tracking-tight">{value ?? 0}</p>
			<p className={`mt-2 text-xs ${accent || "muted"}`}>{detail}</p>
		</div>
	);
}

function FindingCard({ finding }) {
	const [expanded, setExpanded] = useState(false);
	const ai = finding.ai_analysis || {};
	const evidence = Array.isArray(finding.evidence)
		? finding.evidence
		: finding.evidence
			? [String(finding.evidence)]
			: [];

	return (
		<article className="panel p-5">
			<div className="flex flex-wrap items-start justify-between gap-3">
				<div className="min-w-0 flex-1">
					<div className="flex flex-wrap items-center gap-2">
						<span
							className={`rounded-md px-2 py-1 text-xs font-semibold ${severityClass(finding.severity)}`}
						>
							{finding.severity || "LOW"}
						</span>
						<span className="text-xs muted">{finding.category || "Other"}</span>
						{finding.id && (
							<span className="text-xs muted">· {finding.id}</span>
						)}
					</div>

					<h3 className="mt-3 font-semibold text-[#30352d]">
						{finding.title || "Untitled finding"}
					</h3>

					<p className="mt-1 break-all text-xs muted">
						{finding.file || "Unknown file"}
						{finding.line ? ` : ${finding.line}` : ""}
					</p>
				</div>

				<span
					className={`rounded-md px-2.5 py-1 text-xs font-medium ${verdictClass(ai.verdict)}`}
				>
					AI: {(ai.verdict || "UNCERTAIN").replace("_", " ")}
				</span>
			</div>

			<p className="mt-4 text-sm leading-6 text-[#666d61]">
				{finding.description || "No description available."}
			</p>

			<button
				onClick={() => setExpanded(!expanded)}
				className="mt-4 text-sm font-medium text-[#647b55] hover:text-[#3f5837]"
			>
				{expanded ? "Hide details ↑" : "View analysis and recommendation ↓"}
			</button>

			{expanded && (
				<div className="mt-4 space-y-4 border-t border-[#eceee7] pt-4">
					<div>
						<p className="text-xs font-semibold uppercase tracking-wide muted">
							AI reasoning
						</p>
						<p className="mt-1 text-sm leading-6">
							{ai.reasoning || "AI reasoning unavailable."}
						</p>
					</div>

					<div>
						<p className="text-xs font-semibold uppercase tracking-wide muted">
							Potential impact
						</p>
						<p className="mt-1 text-sm leading-6">
							{ai.impact || "Impact not determined."}
						</p>
					</div>

					<div>
						<p className="text-xs font-semibold uppercase tracking-wide muted">
							Recommended fix
						</p>
						<p className="mt-1 text-sm leading-6">
							{ai.recommendation || "Manual review recommended."}
						</p>
					</div>

					<div className="flex flex-wrap gap-3 text-xs muted">
						<span>Confidence: {Math.round((ai.confidence || 0) * 100)}%</span>
						{ai.provider && <span>Provider: {ai.provider}</span>}
					</div>

					{finding.source_context && (
						<div>
							<p className="mb-2 text-xs font-semibold uppercase tracking-wide muted">
								Source context
							</p>
							<pre className="overflow-x-auto rounded-lg bg-[#f5f6f1] p-3 text-xs leading-6 text-[#41483c]">
								{finding.source_context}
							</pre>
						</div>
					)}

					{evidence.length > 0 && (
						<div>
							<p className="mb-2 text-xs font-semibold uppercase tracking-wide muted">
								Detection evidence
							</p>
							{evidence.map((item, index) => (
								<p key={index} className="mb-1 text-sm text-[#666d61]">
									• {item}
								</p>
							))}
						</div>
					)}

					{finding.categories?.length > 0 && (
						<p className="text-xs muted">
							Categories: {finding.categories.join(", ")}
						</p>
					)}
				</div>
			)}
		</article>
	);
}

export default function App() {
	const [repoPath, setRepoPath] = useState("");
	const [data, setData] = useState(null);
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState("");
	const [category, setCategory] = useState("All");
	const [severity, setSeverity] = useState("All");
	const [search, setSearch] = useState("");

	const runAudit = async (event) => {
		event.preventDefault();

		if (!repoPath.trim()) {
			setError("Please enter a repository path.");
			return;
		}

		setLoading(true);
		setError("");
		setData(null);
		setCategory("All");
		setSeverity("All");

		try {
			const response = await fetch(`${API_URL}/api/audit`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(
					repoPath.trim().startsWith("https://github.com/")
						? { github_url: repoPath.trim() }
						: { repo_path: repoPath.trim() },
				),
			});

			const result = await response.json();

			if (!response.ok) {
				throw new Error(
					result.detail || result.message || "Audit request failed.",
				);
			}

			setData(result);
		} catch (err) {
			setError(
				err.message === "Failed to fetch"
					? "Cannot connect to CodeSentinel API. Make sure FastAPI is running."
					: err.message,
			);
		} finally {
			setLoading(false);
		}
	};

	const downloadJSON = () => {
		if (!data) return;

		const json = JSON.stringify(data, null, 2);

		const blob = new Blob([json], {
			type: "application/json",
		});

		const url = URL.createObjectURL(blob);

		const link = document.createElement("a");
		link.href = url;

		const timestamp = new Date().toISOString().replace(/[:.]/g, "-");

		link.download = `codesentinel-report-${timestamp}.json`;

		document.body.appendChild(link);
		link.click();
		document.body.removeChild(link);

		URL.revokeObjectURL(url);
	};

	const findings = data?.findings || [];
	const summary = data?.audit_summary || {};

	const categories = useMemo(() => {
		return [
			"All",
			...new Set(
				findings.flatMap((item) =>
					item.categories?.length
						? item.categories
						: [item.category || "Other"],
				),
			),
		];
	}, [findings]);

	const filteredFindings = useMemo(() => {
		return findings.filter((item) => {
			const itemCategories = item.categories?.length
				? item.categories
				: [item.category || "Other"];

			const matchesCategory =
				category === "All" || itemCategories.includes(category);

			const matchesSeverity = severity === "All" || item.severity === severity;

			const query = search.toLowerCase();

			const matchesSearch = [
				item.title,
				item.description,
				item.file,
				item.id,
			].some((value) =>
				String(value || "")
					.toLowerCase()
					.includes(query),
			);

			return matchesCategory && matchesSeverity && matchesSearch;
		});
	}, [findings, category, severity, search]);

	const ai = summary.ai_validation || {};

	return (
		<main className="min-h-screen bg-[#f7f7f3]">
			<header className="border-b border-[#e9eae3] bg-white">
				<div className="mx-auto flex max-w-7xl items-center justify-between px-5 py-4">
					<div className="flex items-center gap-3">
						<div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[#e9eee3] text-lg font-bold text-[#536b48]">
							C
						</div>
						<div>
							<h1 className="text-lg font-bold tracking-tight">CodeSentinel</h1>
							<p className="text-xs muted">Code quality & security auditor</p>
						</div>
					</div>

					<span className="rounded-full bg-[#edf4e9] px-3 py-1.5 text-xs font-medium text-[#52734d]">
						Local analysis
					</span>
				</div>
			</header>

			<div className="mx-auto max-w-7xl space-y-7 px-5 py-8">
				<section>
					<p className="text-sm font-medium text-[#718267]">
						REPOSITORY ANALYSIS
					</p>
					<h2 className="mt-2 text-3xl font-semibold tracking-tight">
						Understand your codebase.
					</h2>
					<p className="mt-2 max-w-2xl text-sm leading-6 muted">
						Scan repositories for security risks, coding gaps, unfinished work,
						and potential code-quality issues.
					</p>
				</section>

				<form onSubmit={runAudit} className="panel p-5">
					<label className="mb-2 block text-sm font-semibold">
						Repository path or GitHub URL
					</label>

					<div className="flex flex-col gap-3 sm:flex-row">
						<input
							value={repoPath}
							onChange={(e) => setRepoPath(e.target.value)}
							placeholder="C:\\Projects\\my-app or https://github.com/owner/repository"
							className="min-w-0 flex-1 rounded-lg border border-[#e2e5dc] bg-[#fafbf8] px-4 py-3 text-sm outline-none transition focus:border-[#91a481] focus:ring-2 focus:ring-[#e5ecdf]"
						/>

						<button
							type="submit"
							disabled={loading}
							className="rounded-lg bg-[#536b48] px-6 py-3 text-sm font-semibold text-white transition hover:bg-[#43583a] disabled:cursor-not-allowed disabled:opacity-60"
						>
							{loading ? "Scanning..." : "Run full audit"}
						</button>
					</div>

					{error && <p className="mt-3 text-sm text-[#b42318]">{error}</p>}

					{loading && (
						<div className="mt-5">
							<div className="h-1.5 overflow-hidden rounded-full bg-[#edf0e9]">
								<div className="h-full w-1/2 animate-pulse rounded-full bg-[#839b73]" />
							</div>
							<p className="mt-2 text-xs muted">
								Running static analyzers and AI validation. This may take a
								little while.
							</p>
						</div>
					)}
				</form>

				{data && (
					<>
						<section>
							<div className="mb-4 flex flex-wrap items-center justify-between gap-3">
								<div>
									<h3 className="text-lg font-semibold">Audit overview</h3>
									<p className="mt-1 text-xs muted">
										{data.repository?.name || data.repository?.root || repoPath}
									</p>
								</div>

								<div className="flex items-center gap-3">
									<span className="rounded-full bg-[#edf4e9] px-3 py-1.5 text-xs font-medium text-[#52734d]">
										{data.status || "completed"}
									</span>

									<button
										onClick={downloadJSON}
										className="flex items-center gap-2 rounded-lg border border-[#dfe4d9] bg-white px-4 py-2.5 text-sm font-medium text-[#536b48] transition hover:bg-[#f1f4ed]"
									>
										<span>↓</span>
										Download JSON
									</button>
								</div>
							</div>

							<div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
								<StatCard
									label="Total findings"
									value={summary.total_findings}
									detail="Unique findings"
								/>
								<StatCard
									label="Critical"
									value={summary.critical}
									detail="Immediate attention"
									accent="text-[#b42318]"
								/>
								<StatCard
									label="High"
									value={summary.high}
									detail="High priority"
									accent="text-[#bd5b28]"
								/>
								<StatCard
									label="Medium"
									value={summary.medium}
									detail="Needs review"
									accent="text-[#96701b]"
								/>
								<StatCard
									label="Low"
									value={summary.low}
									detail="Lower priority"
									accent="text-[#52734d]"
								/>
							</div>
						</section>

						<section>
							<h3 className="mb-4 text-lg font-semibold">AI validation</h3>
							<div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
								<StatCard
									label="Confirmed"
									value={ai.confirmed}
									detail="Validated findings"
								/>
								<StatCard
									label="Likely"
									value={ai.likely}
									detail="Probable findings"
								/>
								<StatCard
									label="False positives"
									value={ai.false_positives}
									detail="AI flagged for review"
								/>
								<StatCard
									label="Uncertain"
									value={ai.uncertain}
									detail="Manual review recommended"
								/>
							</div>
						</section>

						<section>
							<div className="mb-4">
								<h3 className="text-lg font-semibold">Findings</h3>
								<p className="mt-1 text-sm muted">
									Showing {filteredFindings.length} of {findings.length}{" "}
									findings
								</p>
							</div>

							<div className="panel mb-4 flex flex-col gap-3 p-4 md:flex-row">
								<input
									value={search}
									onChange={(e) => setSearch(e.target.value)}
									placeholder="Search findings..."
									className="min-w-0 flex-1 rounded-lg border border-[#e2e5dc] bg-[#fafbf8] px-3 py-2.5 text-sm outline-none focus:border-[#91a481]"
								/>

								<select
									value={category}
									onChange={(e) => setCategory(e.target.value)}
									className="rounded-lg border border-[#e2e5dc] bg-white px-3 py-2.5 text-sm outline-none"
								>
									{categories.map((item) => (
										<option key={item} value={item}>
											{item}
										</option>
									))}
								</select>

								<select
									value={severity}
									onChange={(e) => setSeverity(e.target.value)}
									className="rounded-lg border border-[#e2e5dc] bg-white px-3 py-2.5 text-sm outline-none"
								>
									{["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map(
										(item) => (
											<option key={item} value={item}>
												{item === "All" ? "All severities" : item}
											</option>
										),
									)}
								</select>
							</div>

							<div className="space-y-3">
								{filteredFindings.length ? (
									filteredFindings.map((finding, index) => (
										<FindingCard
											key={`${finding.file}-${finding.line}-${finding.id}-${index}`}
											finding={finding}
										/>
									))
								) : (
									<div className="panel p-10 text-center">
										<p className="font-medium">
											No findings match your filters.
										</p>
										<p className="mt-1 text-sm muted">
											Try changing the category, severity, or search term.
										</p>
									</div>
								)}
							</div>
						</section>
					</>
				)}

				{!data && !loading && (
					<section className="panel px-6 py-14 text-center">
						<div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-[#edf1e8] text-2xl">
							◈
						</div>
						<h3 className="mt-4 font-semibold">Ready to inspect your code</h3>
						<p className="mx-auto mt-2 max-w-md text-sm leading-6 muted">
							Enter a local repository path above and run a full audit to see
							security issues, code-quality gaps, and AI-assisted analysis.
						</p>
					</section>
				)}

				<footer className="border-t border-[#e5e7df] py-5 text-center text-xs muted">
					CodeSentinel · Static analysis supported by AI validation
				</footer>
			</div>
		</main>
	);
}
