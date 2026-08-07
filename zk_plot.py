#!/usr/bin/env python3
# Copyright (C) 2024 ZK-eSIM contributors
#
# Plotting for the ZK-eSIM server benchmark, split out from measurement so a
# recorded run can be re-drawn without paying for it again.
#
#   python3 zk_server_bench.py -R 200000,600000,1000000 --json results.json
#   python3 zk_plot.py results.json --plot fig.pdf --plot-width 3.33 \
#           --plot-fontsize 8 --plot-aspect 1.0
#
# The JSON written by --json is the interchange format, so a single expensive
# sweep can be re-plotted at as many widths, fonts and aspect ratios as the
# paper needs. zk_server_bench.py imports plot_load() and add_plot_args() from
# here, so the inline --plot path and the standalone tool cannot drift apart.
"""Re-draw ZK-eSIM benchmark results recorded by --json."""

import argparse
import json
import sys

# Role keys as they appear in the recorded JSON.
SMDP, MNO, PCA = 'smdp', 'mno', 'pca'
SERVER_ORDER = (SMDP, MNO, PCA)

# Display names. Recorded files carry their own labels (see LOAD_LABELS use
# below); this is the fallback for JSON written before that was added.
SERVER_LABELS = {SMDP: 'SM-DP+', MNO: 'MNO', PCA: 'PCA'}


def _label(load, server):
    """Display name for a role, preferring whatever the JSON recorded."""
    return (load.get(server, {}).get('label')
            or SERVER_LABELS.get(server, str(server)))


# Categorical palette, fixed order, one slot per server role -- never cycled.
# Validated for all-pairs CVD separation and normal-vision distance on a light
# surface; the aqua slot sits under 3:1 contrast, which is why every series is
# also directly labelled at its last point rather than identified by colour alone.
PLOT_SURFACE = '#fcfcfb'
PLOT_INK = '#0b0b0b'
PLOT_INK_MUTED = '#52514e'
PLOT_GRID = '#dedcd6'
PLOT_SERIES = {SMDP: '#2a78d6', MNO: '#eb6834', PCA: '#1baf7a'}
# Distinct shapes as well as hues: in the compact layout the legend is the
# only identifier, and the aqua slot sits under 3:1 contrast, so identity
# must not rest on colour alone.
PLOT_MARKERS = {SMDP: 'o', MNO: 's', PCA: '^'}

# Times first, then metric-compatible clones, then a generic serif backstop.
PLOT_FONT_STACK = ['Times New Roman', 'Nimbus Roman', 'Liberation Serif',
                   'FreeSerif', 'DejaVu Serif']


def _abbrev(v, _pos=None):
    """Short axis ticks for a narrow column: 200k, 1.0M."""
    if v >= 1e6:
        return f'{v / 1e6:g}M'
    if v >= 1e3:
        return f'{v / 1e3:g}k'
    return f'{v:g}'


def _resolve_serif(matplotlib):
    """Which entry of PLOT_FONT_STACK will actually be used, if any."""
    from matplotlib import font_manager
    installed = {f.name for f in font_manager.fontManager.ttflist}
    return next((n for n in PLOT_FONT_STACK if n in installed), None)


def plot_load(load, args, path):
    """Chart peak memory and CPU against total request count, one line per role.

    Two stacked panels rather than one chart with twin y-axes: memory and CPU
    share no scale, and a second y-axis invites the reader to compare gradients
    that are not comparable.
    """
    try:
        import matplotlib
        matplotlib.use('Agg')                      # headless: no display needed
        import matplotlib.pyplot as plt
        from matplotlib.ticker import FuncFormatter, MaxNLocator
    except ImportError:
        print('[plot]  matplotlib not installed — skipping (pip install matplotlib)',
              file=sys.stderr)
        return None

    # Times, with metric-compatible fallbacks.  Times New Roman is a Microsoft
    # font and is usually absent on Linux (install ttf-mscorefonts-installer to
    # get the real thing); Nimbus Roman and Liberation Serif are Times clones
    # that match its metrics closely enough for a paper figure.  The fallback
    # chain matters because matplotlib does not fail on a missing family -- it
    # silently drops to DejaVu Sans, so asking for Times and not checking would
    # quietly produce a sans-serif chart.
    matplotlib.rcParams['font.family'] = 'serif'
    matplotlib.rcParams['font.serif'] = (
        PLOT_FONT_STACK + list(matplotlib.rcParamsDefault['font.serif']))
    matplotlib.rcParams['mathtext.fontset'] = 'stix'   # Times-metric math
    resolved = _resolve_serif(matplotlib)
    if resolved and resolved != PLOT_FONT_STACK[0]:
        print(f'[plot]  "{PLOT_FONT_STACK[0]}" not installed — rendering in '
              f'"{resolved}" (metric-compatible)', file=sys.stderr)

    servers = [s for s in SERVER_ORDER if s in load]
    if not servers:
        return None

    # Render at the size the figure will be PRINTED, so LaTeX includes it at
    # scale 1.0 and a point here is a point on the page.  Growing the canvas
    # and the point size together is self-defeating: \includegraphics scales
    # the figure to \columnwidth, so a wider canvas is divided down harder and
    # the printed type barely moves.
    width = float(getattr(args, 'plot_width', None) or 7.0)
    fs = float(getattr(args, 'plot_fontsize', None) or 9.0)
    aspect = float(getattr(args, 'plot_aspect', None) or 0.82)
    # A single column is too narrow to shrink the wide layout into: the
    # direct labels alone claim a third of the width. Below ~5in the chart
    # switches to a layout designed for that width -- legend instead of
    # per-point labels, abbreviated ticks, and x labels on the lower panel
    # only -- which buys the space back for the data.
    compact = width < 5.0
    show_title = not getattr(args, 'plot_no_title', False)

    # Type scale, as multiples of the base size. In a column the chrome has to
    # earn its space: at the wide ratios the headings, legend and axis
    # furniture consumed well over half the canvas and left each panel under a
    # quarter of it, so the compact column runs a flatter scale -- the heading
    # barely above body size, ticks below it -- to hand that space to the data.
    if compact:
        r_title, r_panel, r_axis = 1.10, 0.90, 1.00
        r_tick, r_label, r_legend = 0.90, 0.90, 0.90
    else:
        r_title, r_panel, r_axis = 1.45, 1.10, 1.10
        r_tick, r_label, r_legend = 1.00, 1.00, 1.05
    fs_title, fs_panel, fs_axis = fs * r_title, fs * r_panel, fs * r_axis
    fs_tick, fs_label, fs_legend = fs * r_tick, fs * r_label, fs * r_legend
    line_w = max(0.9, fs * 0.17)
    mark_s = max(3.0, fs * 0.58)

    fig, (ax_mem, ax_cpu) = plt.subplots(2, 1, figsize=(width, width * aspect),
                                         dpi=300, sharex=True)
    fig.patch.set_facecolor(PLOT_SURFACE)
    # Explicit margins rather than bbox_inches='tight': the title block and the
    # legend are placed in figure coordinates, and letting savefig re-crop
    # afterwards moves them relative to the panels.
    #
    # Margins in INCHES, converted to the fractions subplots_adjust wants, and
    # derived from the size of the text that actually sits in them rather than
    # from the base font size. That coupling is the point: shrinking a heading
    # now widens the plot instead of just leaving a gap.
    fig_h = width * aspect
    pad_top = 0.05 if compact else 0.08
    # The top band is a stack: figure heading (optional), legend, then the
    # first panel's heading. Sizing them separately is what stops the legend
    # landing on the panel heading.
    # Side margins first: they do not depend on the heading, and the heading's
    # wrap depends on them.
    m_left = 0.10 + (fs_tick * 2.7 + fs_axis * 1.6) / 72.0   # y ticks + y title
    m_right = 0.08
    # Bottom margin trimmed close to what the two lines of text actually
    # need. Anything beyond that is dead space baked into the PDF, which
    # LaTeX cannot claw back -- it reads as a gap before the caption.
    m_bot = 0.04 + (fs_tick * 1.5 + fs_axis * 1.5) / 72.0    # x ticks + x title
    # Wrap the heading now and reserve room for the lines it ACTUALLY takes.
    # Assuming a fixed two lines in a column left a dead band whenever the
    # heading happened to fit on one.
    heading = ''
    if show_title:
        import textwrap
        avail_pt = (width - m_left - m_right) * 72
        chars = max(14, int(avail_pt / (fs_title * 0.52)))
        heading = '\n'.join(textwrap.wrap(
            'ZK-eSIM memory and CPU usage server load', chars))
    _title_lines = (heading.count('\n') + 1) if heading else 0
    band_title = (fs_title * 1.35 / 72.0) * _title_lines
    band_legend = fs_legend * 1.6 / 72.0
    band_heading = fs_panel * 1.5 / 72.0
    # One spacing constant, spent both between the panels and between the
    # legend and the first panel, so those two gaps stay equal by construction
    # instead of having to be re-matched by hand whenever a size changes.
    lead = 0.12 if compact else 0.20
    m_top = pad_top + band_title + band_legend + lead + band_heading
    gap = ((lead + band_heading) if compact
           else (lead + (fs_tick * 1.7 + fs_axis * 1.7) / 72.0 + band_heading))
    axes_h = max(0.35, (fig_h - m_top - m_bot - gap) / 2.0)
    fig.subplots_adjust(top=1 - m_top / fig_h, bottom=m_bot / fig_h,
                        left=m_left / width, right=1 - m_right / width,
                        hspace=gap / axes_h)

    panels = [
        # The memory series is PSS (shared pages divided by the number of
        # processes mapping them), which is what totals the real footprint once
        # across parent + workers -- see the load section's notes.
        (ax_mem, 'Peak Memory Usage', 'peak usage (MB)',
         lambda r: r['pss_peak_total_bytes'] / 2**20, '{:.0f} MB'),
        (ax_cpu, 'CPU Seconds Consumed', 'CPU seconds',
         lambda r: r['cpu_seconds'], '{:.1f} s'),
    ]

    all_x = [r['total_requests'] for s in servers for r in load[s]['levels']]
    lo, hi = min(all_x), max(all_x)
    # Right-hand end of the x-axis. --plot-xmax pins it; otherwise leave
    # headroom past the last point for the direct labels to sit in.
    x_right = getattr(args, 'plot_xmax', None) or hi + (hi - lo) * 0.46
    if x_right <= hi:
        print(f'[plot]  --plot-xmax ({x_right:,.0f}) is at or below the largest '
              f'request total ({hi:,}); labels would fall outside the axes',
              file=sys.stderr)

    for ax, title, ylabel, getter, lab_fmt in panels:
        ax.set_facecolor(PLOT_SURFACE)
        ends = []
        for server in servers:
            rows = load[server]['levels']
            xs = [r['total_requests'] for r in rows]
            ys = [getter(r) for r in rows]
            colour = PLOT_SERIES[server]
            ax.plot(xs, ys, color=colour, linewidth=line_w,
                    marker=PLOT_MARKERS[server], markersize=mark_s,
                    markeredgecolor=PLOT_SURFACE, markeredgewidth=1.5,
                    label=_label(load, server), zorder=3, clip_on=False)
            # [point y, label y (adjusted below), point x, text]
            ends.append([ys[-1], ys[-1], xs[-1],
                         f"{_label(load, server)}  {lab_fmt.format(ys[-1])}"])

        ax.set_title(title, color=PLOT_INK, fontsize=fs_panel, loc='left', pad=4)
        ax.set_ylabel(ylabel, color=PLOT_INK_MUTED, fontsize=fs_axis)
        ax.grid(True, color=PLOT_GRID, linewidth=0.8, alpha=0.9, zorder=0)
        ax.set_axisbelow(True)
        for side in ('top', 'right'):
            ax.spines[side].set_visible(False)
        for side in ('left', 'bottom'):
            ax.spines[side].set_color(PLOT_GRID)
        # labelbottom: sharex hides the upper panel's tick labels by default,
        # which leaves the top chart with an unlabelled x-axis. Both panels get
        # their own ticks and axis title; sharex is kept only so the two stay on
        # an identical x scale.
        is_last = ax is panels[-1][0]
        ax.tick_params(colors=PLOT_INK_MUTED, labelsize=fs_tick,
                       labelbottom=(is_last or not compact))
        if is_last or not compact:
            ax.set_xlabel('total requests served', color=PLOT_INK_MUTED,
                          fontsize=fs_axis)
        ax.xaxis.set_major_formatter(FuncFormatter(_abbrev if compact
                                                   else lambda v, _: f'{v:,.0f}'))
        if compact:
            ax.xaxis.set_major_locator(MaxNLocator(nbins=4, prune=None))
        # Headroom above the marks so a flat series is not pinned to the frame,
        # and to the right so the direct labels have somewhere to sit.
        top = max(e[0] for e in ends) or 1.0
        ax.set_ylim(0, top * 1.35)
        # --plot-xmax pins the right-hand end; otherwise leave enough room past
        # the last point for the direct labels to sit in.
        ax.set_xlim(lo - (hi - lo) * 0.02,
                    hi + (hi - lo) * 0.06 if compact else x_right)

        # Direct labels, de-collided.  The roles can land within 1% of each
        # other -- memory in particular is near-identical across them -- so
        # labels placed at the mark would overprint into mush.  Push them apart
        # to a minimum vertical gap and run a leader back to the point.
        if compact:
            continue          # legend carries identity; no room for labels
        gap = ax.get_ylim()[1] * 0.125
        ends.sort(key=lambda e: e[0])
        for i in range(1, len(ends)):
            ends[i][1] = max(ends[i][1], ends[i - 1][1] + gap)
        for point_y, label_y, x_end, text in ends:
            # Text wears ink, never the series colour -- the marker carries
            # identity. This also discharges the low-contrast slot's relief
            # requirement, since every series is named in place.
            ax.annotate(text, xy=(x_end, point_y),
                        xytext=(hi + (x_right - hi) * 0.10, label_y),
                        textcoords='data', va='center', fontsize=fs_label,
                        color=PLOT_INK, zorder=4,
                        arrowprops=dict(arrowstyle='-', color=PLOT_GRID,
                                        linewidth=0.8, shrinkA=0, shrinkB=4))

    # Legend as well as the direct labels: identity is never colour-alone.
    # Figure-level and above the panels, so it cannot land on the marks.
    handles, labels = ax_mem.get_legend_handles_labels()
    fig.legend(handles, labels, frameon=False, fontsize=fs_legend,
               labelcolor=PLOT_INK_MUTED, loc='upper left',
               bbox_to_anchor=(m_left / width,
                               1 - (pad_top + band_title) / fig_h),
               ncols=len(servers))

    # how = ('one per CPU core' if args.workers == DEFAULT_WORKERS
    #        else f'on a {DEFAULT_WORKERS}-core host')
    if show_title:
        # Wrapped above, against the space BETWEEN the margins rather than the
        # whole canvas, using a realistic average glyph width for Times.
        fig.suptitle(heading, color=PLOT_INK, fontsize=fs_title,
                     x=m_left / width, ha='left', y=1 - pad_top / fig_h,
                     va='top', linespacing=1.15)
    # Format follows the extension: --plot load.pdf gives vector output for
    # LaTeX, --plot load.png a raster. Pinning format= here would write a PDF
    # into a file named .png.
    fig.savefig(path, facecolor=PLOT_SURFACE)
    plt.close(fig)
    return path



def add_plot_args(ap):
    """Plot options, shared so both entry points expose the same flags."""
    ap.add_argument('--plot-width', type=float, default=7.0, metavar='INCHES',
                    help='figure width in inches — set this to the width it will '
                         'occupy in the paper so LaTeX includes it unscaled '
                         '(ACM sigconf: 7.0 for figure*, 3.33 for a single '
                         'column). Below 5in a compact layout is used. Default: 7.0')
    ap.add_argument('--plot-fontsize', type=float, default=9.0, metavar='PT',
                    help='base font size in points. Because the figure is drawn '
                         'at its printed width, this IS the size on the page — '
                         'match it to the document body text. Default: 9')
    ap.add_argument('--plot-aspect', type=float, default=0.82, metavar='R',
                    help='figure height as a fraction of its width. Lower is '
                         'flatter, which a two-column float places more easily. '
                         'Default: 0.82')
    ap.add_argument('--plot-no-title', action='store_true',
                    help='omit the heading drawn inside the figure — in a paper '
                         'the \\caption carries it, and dropping it frees '
                         'vertical space')
    ap.add_argument('--plot-xmax', type=float, default=None, metavar='N',
                    help='cut the plot x-axis off at this request count (e.g. '
                         '1300000). Default: just past the largest total, with '
                         'room for the direct labels.')
    return ap


def main(argv):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('results', help='JSON file written by zk_server_bench.py --json')
    ap.add_argument('--plot', metavar='PATH', default='zk_load.pdf',
                    help='output path; the extension picks the format '
                         '(.pdf for LaTeX, .png for a raster). Default: zk_load.pdf')
    add_plot_args(ap)
    args = ap.parse_args(argv)

    try:
        with open(args.results) as fh:
            payload = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f'could not read {args.results}: {exc}')

    load = payload.get('load') or {}
    if not load:
        raise SystemExit(
            f'{args.results} has no load data — it was recorded without -R/--requests. '
            f'Re-run the benchmark with e.g. -R 200000,600000,1000000 --json ...')

    env = payload.get('env', {})
    if env.get('workers'):
        args.workers = env['workers']          # recorded, not re-specified
    else:
        args.workers = load[next(iter(load))].get('workers', 1)

    totals = sorted({r['total_requests'] for s in load.values() for r in s['levels']})
    print(f'[plot]  {args.results}: {len(load)} role(s), '
          f'{len(totals)} request totals ({totals[0]:,}..{totals[-1]:,}), '
          f'{args.workers} workers', file=sys.stderr)

    if plot_load(load, args, args.plot):
        print(f'[plot]  wrote {args.plot} '
              f'({args.plot_width:g}in wide, {args.plot_fontsize:g}pt base)')
        print(f'[plot]  include it UNSCALED so the type stays at '
              f'{args.plot_fontsize:g}pt on the page:')
        print(f'[plot]    \\includegraphics[width={args.plot_width:g}in]'
              f'{{{args.plot}}}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
