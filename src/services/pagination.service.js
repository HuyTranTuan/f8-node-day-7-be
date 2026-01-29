class PaginationServices {
  async apply(services) {
    services.pagination = async (page = 1, limit = 20) => {
      let offset = (page - 1) * limit;

      const rows = await services.model.pagination(
        limit,
        offset,
        services.userID || undefined,
      );
      const total = await services.model.count(services.userID || undefined);
      const length = rows.length;

      return {
        rows,
        pagination: {
          total,
          per_page: limit,
          from: length > 0 ? offset + 1 : 0,
          to: length > 0 ? offset + length : 0,
          current_page: page,
        },
      };
    };
  }
}

module.exports = new PaginationServices();
