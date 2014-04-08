using System.ComponentModel;
using System.Linq;
using ASPNETIdentityWithOnion.Core.DomainModels;

namespace ASPNETIdentityWithOnion.Core.Extensions
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static class QueryableExtensions
    {
        public static PaginatedList<T> ToPaginatedList<T>(this IQueryable<T> query, int pageIndex, int pageSize, int total)
        {
            var list = query.ToList();
            return new PaginatedList<T>(list, pageIndex, pageSize, total);
        }

        public static IQueryable<T> Paginate<T>(this IQueryable<T> query, int pageIndex, int pageSize)
        {
            var entities = query.Skip((pageIndex - 1)*pageSize).Take(pageSize);
            return entities;
        }
    }
}