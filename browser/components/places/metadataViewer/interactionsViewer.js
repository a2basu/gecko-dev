/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* eslint-env module */

const { Interactions } = ChromeUtils.import(
  "resource:///modules/Interactions.jsm"
);
const { Services } = ChromeUtils.import("resource://gre/modules/Services.jsm");
const { Snapshots } = ChromeUtils.import("resource:///modules/Snapshots.jsm");
const { PlacesUtils } = ChromeUtils.import(
  "resource://gre/modules/PlacesUtils.jsm"
);

/**
 * Base class for the table display. Handles table layout and updates.
 */
class TableViewer {
  /**
   * Maximum number of rows to display by default.
   *
   * @typedef {number}
   */
  maxRows = 100;

  /**
   * The number of rows that we last filled in on the table. This allows
   * tracking to know when to clear unused rows.
   * @typedef {number}
   */
  #lastFilledRows = 0;

  /**
   * A map of columns that are displayed by default. This is set by sub-classes.
   *
   * - The key is the column name in the database.
   * - The header is the column header on the table.
   * - The modifier is a function to modify the returned value from the database
   *   for display.
   * - includeTitle determines if the title attribute should be set on that
   *   column, for tooltips, e.g. if an element is likely to overflow.
   *
   * @typedef {Map<string, object>}
   */
  columnMap;

  /**
   * A reference for the current interval timer, if any.
   * @typedef {number}
   */
  #timer;

  /**
   * Starts the display of the table. Setting up the table display and doing
   * an initial output. Also starts the interval timer.
   */
  async start() {
    this.setupUI();
    await this.updateDisplay();
    this.#timer = setInterval(this.updateDisplay.bind(this), 10000);
  }

  /**
   * Pauses updates for this table, use start() to re-start.
   */
  pause() {
    if (this.#timer) {
      clearInterval(this.#timer);
      this.#timer = null;
    }
  }

  /**
   * Creates the initial table layout and sets the styles to match the number
   * of columns.
   */
  setupUI() {
    document.getElementById("title").textContent = this.title;

    let viewer = document.getElementById("tableViewer");
    viewer.textContent = "";

    // Set up the table styles.
    let existingStyle = document.getElementById("tableStyle");
    let numColumns = this.columnMap.size;
    let styleText = `
#tableViewer {
  display: grid;
  grid-template-columns: ${this.cssGridTemplateColumns}
}

/* Sets the first row of elements to bold. The number is the number of columns */
#tableViewer > div:nth-child(-n+${numColumns}) {
  font-weight: bold;
}

/* Highlights every other row to make visual scanning of the table easier.
   The numbers need to be adapted if the number of columns changes. */
`;
    for (let i = numColumns + 1; i <= numColumns * 2 - 1; i++) {
      styleText += `#tableViewer > div:nth-child(${numColumns}n+${i}):nth-child(${numColumns *
        2}n+${i}),\n`;
    }
    styleText += `#tableViewer > div:nth-child(${numColumns}n+${numColumns *
      2}):nth-child(${numColumns * 2}n+${numColumns * 2})\n
{
  background: var(--in-content-box-background-odd);
}`;
    existingStyle.innerText = styleText;

    // Now set up the table itself with empty cells, this avoids having to
    // create and delete rows all the time.
    let tableBody = document.createDocumentFragment();
    let header = document.createDocumentFragment();
    for (let details of this.columnMap.values()) {
      let columnDiv = document.createElement("div");
      columnDiv.textContent = details.header;
      header.appendChild(columnDiv);
    }
    tableBody.appendChild(header);

    for (let i = 0; i < this.maxRows; i++) {
      let row = document.createDocumentFragment();
      for (let j = 0; j < this.columnMap.size; j++) {
        row.appendChild(document.createElement("div"));
      }
      tableBody.appendChild(row);
    }
    viewer.appendChild(tableBody);

    let limit = document.getElementById("tableLimit");
    limit.textContent = `Maximum rows displayed: ${this.maxRows}.`;

    this.#lastFilledRows = 0;
  }

  /**
   * Displays the provided data in the table.
   *
   * @param {object[]} rows
   *   An array of rows to display. The rows are objects with the values for
   *   the rows being the keys of the columnMap.
   */
  displayData(rows) {
    let viewer = document.getElementById("tableViewer");
    let index = this.columnMap.size;
    for (let row of rows) {
      for (let [column, details] of this.columnMap.entries()) {
        let value = row[column];

        if (details.includeTitle) {
          viewer.children[index].setAttribute("title", value);
        }

        viewer.children[index].textContent = details.modifier
          ? details.modifier(value)
          : value;

        index++;
      }
    }
    let numRows = rows.length;
    if (numRows < this.#lastFilledRows) {
      for (let r = numRows; r < this.#lastFilledRows; r++) {
        for (let c = 0; c < this.columnMap.size; c++) {
          viewer.children[index].textContent = "";
          viewer.children[index].removeAttribute("title");
          index++;
        }
      }
    }
    this.#lastFilledRows = numRows;
  }
}

/**
 * Viewer definition for the page metadata.
 */
const metadataHandler = new (class extends TableViewer {
  title = "Interactions";
  cssGridTemplateColumns =
    "max-content fit-content(100%) repeat(4, max-content);";

  /**
   * @see TableViewer.columnMap
   */
  columnMap = new Map([
    ["id", { header: "ID" }],
    ["url", { header: "URL", includeTitle: true }],
    [
      "updated_at",
      {
        header: "Updated",
        modifier: updatedAt => new Date(updatedAt).toLocaleString(),
      },
    ],
    [
      "total_view_time",
      {
        header: "View Time (s)",
        modifier: totalViewTime => (totalViewTime / 1000).toFixed(2),
      },
    ],
    [
      "typing_time",
      {
        header: "Typing Time (s)",
        modifier: typingTime => (typingTime / 1000).toFixed(2),
      },
    ],
    ["key_presses", { header: "Key Presses" }],
  ]);

  /**
   * A reference to the database connection.
   *
   * @typedef {mozIStorageConnection}
   */
  #db = null;

  async #getRows(query) {
    if (!this.#db) {
      this.#db = await PlacesUtils.promiseDBConnection();
    }
    let rows = await this.#db.executeCached(query);
    return rows.map(r => {
      let result = {};
      for (let column of this.columnMap.keys()) {
        result[column] = r.getResultByName(column);
      }
      return result;
    });
  }

  /**
   * Loads the current metadata from the database and updates the display.
   */
  async updateDisplay() {
    let rows = await this.#getRows(
      `SELECT m.id AS id, h.url AS url, updated_at, total_view_time,
              typing_time, key_presses FROM moz_places_metadata m
       JOIN moz_places h ON h.id = m.place_id
       ORDER BY updated_at DESC
       LIMIT ${this.maxRows}`
    );
    this.displayData(rows);
  }

  export() {
    // Get all rows in the last 7 days
    return this.#getRows(
      `SELECT m.id AS id, h.url AS url, updated_at, total_view_time,
            typing_time, key_presses FROM moz_places_metadata m
     JOIN moz_places h ON h.id = m.place_id
     WHERE updated_at > strftime('%s','now','localtime','start of day','-7 days','utc') * 1000
     ORDER BY updated_at DESC
     `
    );
  }
})();

/**
 * Viewer definition for the Snapshots data.
 */
const snapshotHandler = new (class extends TableViewer {
  title = "Snapshots";
  cssGridTemplateColumns = "fit-content(100%) repeat(6, max-content);";

  /**
   * @see TableViewer.columnMap
   */
  columnMap = new Map([
    ["url", { header: "URL", includeTitle: true }],
    [
      "createdAt",
      {
        header: "Created",
        modifier: c => c.toLocaleString(),
      },
    ],
    [
      "removedAt",
      {
        header: "Removed",
        modifier: r => r?.toLocaleString() ?? "",
      },
    ],
    [
      "firstInteractionAt",
      {
        header: "First Interaction",
        modifier: f => f.toLocaleString(),
      },
    ],
    [
      "lastInteractionAt",
      {
        header: "Latest Interaction",
        modifier: l => l.toLocaleString(),
      },
    ],
    [
      "documentType",
      {
        header: "Doc Type",
        modifier: d =>
          d == Interactions.DOCUMENT_TYPE.MEDIA ? "Media" : "Generic",
      },
    ],
    [
      "userPersisted",
      {
        header: "User Persisted",
        modifier: u => (u ? "Yes" : ""),
      },
    ],
  ]);

  /**
   * Loads the current metadata from the database and updates the display.
   */
  async updateDisplay() {
    this.displayData(await Snapshots.query({ includeTombstones: true }));
  }
})();

function checkPrefs() {
  if (
    !Services.prefs.getBoolPref("browser.places.interactions.enabled", false)
  ) {
    let warning = document.getElementById("enabledWarning");
    warning.hidden = false;
  }
}

function show(selectedButton) {
  let currentButton = document.querySelector(".category.selected");
  if (currentButton == selectedButton) {
    return;
  }

  currentButton.classList.remove("selected");
  selectedButton.classList.add("selected");

  switch (selectedButton.getAttribute("value")) {
    case "snapshots":
      metadataHandler.pause();
      snapshotHandler.start();
      break;
    case "metadata":
      snapshotHandler.pause();
      metadataHandler.start();
      break;
  }
}

function setupListeners() {
  let menu = document.getElementById("categories");
  menu.addEventListener("click", e => {
    if (e.target && e.target.parentNode == menu) {
      show(e.target);
    }
  });
  document.getElementById("export").addEventListener("click", async e => {
    e.preventDefault();
    const data = await metadataHandler.export();
    const blob = new Blob([JSON.stringify(data)], {
      type: "text/json;charset=utf-8",
    });
    const a = document.createElement("a");
    a.setAttribute("download", `places-${Date.now()}.json`);
    a.setAttribute("href", window.URL.createObjectURL(blob));
    a.click();
    a.remove();
  });
}

checkPrefs();
snapshotHandler.start().catch(console.error);
setupListeners();
